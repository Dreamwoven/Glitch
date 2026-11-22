#include "patch_manager.hpp"
#include "rivet_parser.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <unordered_map>

namespace riftloader {

PatchManager::PatchManager(Logger& logger, Scanner& scanner, MemoryPatcher& patcher, StubAllocator& stubs)
    : logger_(logger), scanner_(scanner), patcher_(patcher), stubs_(stubs) {}

PatchManager::~PatchManager() {
    UnloadAll();
}

namespace {

std::vector<std::string> ParseRequiredManifests(const RivetNode* root) {
    std::vector<std::string> reqs;
    if (!root) return reqs;
    if (const RivetNode* rm = root->Get("required_manifests")) {
        for (const auto& child : rm->ordered_children) {
            if (!child->raw_value.empty()) {
                reqs.push_back(child->raw_value);
            }
        }
    }
    return reqs;
}

} // namespace

void PatchManager::LoadDirectory(const std::string& dir_path,
                                 const std::unordered_set<std::string>& disabled_names) {
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::exists(dir_path, ec)) {
        fs::create_directories(dir_path, ec);
        return;
    }

    std::vector<fs::path> files;
    for (const auto& entry : fs::directory_iterator(dir_path, ec)) {
        if (entry.is_regular_file() && entry.path().extension() == ".rvt") {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());

    struct PendingManifest {
        std::string path;
        RivetParseResult parsed;
        std::string name;
        std::vector<std::string> required_manifests;
        bool in_cycle = false;
    };

    std::vector<PendingManifest> pending;
    pending.reserve(files.size());
    std::unordered_map<std::string, size_t> name_to_idx;

    for (const auto& f : files) {
        std::string pstr = f.string();
        auto parsed = RivetParser::ParseFile(pstr);
        if (!parsed.Ok()) {
            logger_.Log(RIFT_LOG_ERROR, "patches", "Parse failed for %s (line %zu): %s",
                        pstr.c_str(), parsed.error_line, parsed.error.c_str());
            continue;
        }
        PendingManifest pm;
        pm.path = std::move(pstr);
        pm.name = parsed.root->GetString("name", f.stem().string());
        pm.required_manifests = ParseRequiredManifests(parsed.root.get());
        pm.parsed = std::move(parsed);
        name_to_idx[pm.name] = pending.size();
        pending.push_back(std::move(pm));
    }

    // Topological sort so dependencies load before dependents (preserving filename order otherwise).
    // state: 0 = unvisited, 1 = visiting (on stack), 2 = done.
    std::vector<uint8_t> state(pending.size(), 0);
    std::vector<size_t> order;
    order.reserve(pending.size());

    auto dfs = [&](auto& self, size_t idx) -> bool {
        if (state[idx] == 2) return pending[idx].in_cycle;
        if (state[idx] == 1) {
            pending[idx].in_cycle = true;
            return true;
        }
        state[idx] = 1;
        bool hit_cycle = false;
        for (const auto& req : pending[idx].required_manifests) {
            auto it = name_to_idx.find(req);
            if (it != name_to_idx.end()) {
                if (self(self, it->second)) {
                    hit_cycle = true;
                }
            }
        }
        if (hit_cycle) {
            pending[idx].in_cycle = true;
        }
        state[idx] = 2;
        order.push_back(idx);
        return pending[idx].in_cycle;
    };

    for (size_t i = 0; i < pending.size(); ++i) {
        if (state[i] == 0) {
            dfs(dfs, i);
        }
    }

    for (size_t idx : order) {
        const auto& pm = pending[idx];
        std::string cycle_err = pm.in_cycle ? "Circular dependency in required_manifests" : "";
        LoadParsedManifest(pm.path, pm.parsed.root.get(), disabled_names, cycle_err);
    }
}

bool PatchManager::ApplySite(LoadedPatch& lp, const RivetNode& site, bool enable_now, std::string& err) {
    // Resolve target live address: supports `va`, `rva`, `live_addr`, or `pattern` (+ optional `offset`).
    uintptr_t live_addr = 0;

    if (const RivetNode* pn = site.Get("pattern")) {
        std::string pat = pn->AsString();
        std::string sec = site.GetString("section", "");
        RiftResult sr = sec.empty()
            ? scanner_.FindPattern(pat, live_addr)
            : scanner_.FindPatternInSection(sec.c_str(), pat, live_addr);
        if (sr != RIFT_OK) {
            err = "Byte pattern not found: " + pat;
            return false;
        }
        int64_t off = site.GetInt("offset").value_or(0);
        live_addr = static_cast<uintptr_t>(static_cast<int64_t>(live_addr) + off);
    } else if (auto va = site.GetUInt("va")) {
        live_addr = scanner_.VaToLive(*va);
    } else if (auto rva = site.GetUInt("rva")) {
        live_addr = scanner_.RvaToLive(static_cast<uint32_t>(*rva));
    } else if (auto raw = site.GetUInt("live_addr")) {
        live_addr = static_cast<uintptr_t>(*raw);
    } else {
        err = "Patch site missing va/rva/pattern/live_addr";
        return false;
    }

    std::vector<uint8_t> expected_orig;
    if (const RivetNode* on = site.Get("orig")) {
        if (!Scanner::ParseHexBytes(on->AsString(), expected_orig)) {
            err = "Invalid hex in 'orig'";
            return false;
        }
    }

    std::vector<uint8_t> patch_bytes;
    if (const RivetNode* cn = site.Get("stub_bytes")) {
        // Declarative patch stub detour: allocates executable stub, writes stub_bytes + E9 back, patches site with E9 stub + NOPs.
        std::vector<uint8_t> stub;
        if (!Scanner::ParseHexBytes(cn->AsString(), stub)) {
            err = "Invalid hex in 'stub_bytes'";
            return false;
        }
        size_t site_len = static_cast<size_t>(site.GetUInt("detour_len").value_or(expected_orig.size()));
        if (site_len < 5) {
            err = "stub_bytes site requires detour_len >= 5 (or orig >= 5 bytes)";
            return false;
        }

        const bool auto_return = site.GetBool("stub_auto_return", true);
        const size_t total_stub = stub.size() + (auto_return ? 5u : 0u);
        void* stub_mem = stubs_.Alloc(live_addr, total_stub, RIFT_INVALID_HANDLE);
        if (!stub_mem) {
            err = "Failed to allocate executable stub";
            return false;
        }

        uintptr_t stub_va = reinterpret_cast<uintptr_t>(stub_mem);
        int64_t enter_rel = static_cast<int64_t>(stub_va) - static_cast<int64_t>(live_addr + 5);
        if (enter_rel < INT32_MIN || enter_rel > INT32_MAX) {
            stubs_.Free(stub_mem);
            err = "Executable stub out of rel32 range for entry jump";
            return false;
        }

        // Apply optional RIP-relative / rel32 fixups inside the patch stub.
        if (const RivetNode* fx_arr = site.Get("stub_fixups")) {
            for (const auto& fx : fx_arr->ordered_children) {
                auto off_opt = fx->GetUInt("off");
                if (!off_opt || *off_opt + 4 > stub.size()) {
                    stubs_.Free(stub_mem);
                    err = "Invalid or out-of-range 'off' in stub_fixups";
                    return false;
                }
                const size_t disp_off = static_cast<size_t>(*off_opt);
                const size_t next_off = static_cast<size_t>(fx->GetUInt("next_off").value_or(disp_off + 4));

                uintptr_t target_live = 0;
                if (auto tva = fx->GetUInt("target_va")) {
                    target_live = scanner_.VaToLive(*tva);
                } else if (auto trva = fx->GetUInt("target_rva")) {
                    target_live = scanner_.RvaToLive(static_cast<uint32_t>(*trva));
                } else if (auto traw = fx->GetUInt("target_live_addr")) {
                    target_live = static_cast<uintptr_t>(*traw);
                } else {
                    stubs_.Free(stub_mem);
                    err = "stub_fixups entry missing target_va/target_rva/target_live_addr";
                    return false;
                }

                int64_t rel = static_cast<int64_t>(target_live) - static_cast<int64_t>(stub_va + next_off);
                if (rel < INT32_MIN || rel > INT32_MAX) {
                    stubs_.Free(stub_mem);
                    err = "stub_fixups target out of rel32 range";
                    return false;
                }
                int32_t rel32 = static_cast<int32_t>(rel);
                std::memcpy(stub.data() + disp_off, &rel32, 4);
            }
        }

        std::memcpy(stub_mem, stub.data(), stub.size());
        if (auto_return) {
            uintptr_t back_va = live_addr + site_len;
            int64_t back_rel = static_cast<int64_t>(back_va) - static_cast<int64_t>(stub_va + stub.size() + 5);
            if (back_rel < INT32_MIN || back_rel > INT32_MAX) {
                stubs_.Free(stub_mem);
                err = "Executable stub out of rel32 range for return jump";
                return false;
            }
            uint8_t jmp_back[5] = {0xE9};
            int32_t br32 = static_cast<int32_t>(back_rel);
            std::memcpy(jmp_back + 1, &br32, 4);
            std::memcpy(static_cast<uint8_t*>(stub_mem) + stub.size(), jmp_back, 5);
        }
        FlushInstructionCache(GetCurrentProcess(), stub_mem, total_stub);
        lp.stubs.push_back(stub_mem);

        patch_bytes.assign(site_len, 0x90);
        patch_bytes[0] = 0xE9;
        int32_t er32 = static_cast<int32_t>(enter_rel);
        std::memcpy(patch_bytes.data() + 1, &er32, 4);
    } else if (const RivetNode* bn = site.Get("bytes")) {
        if (!Scanner::ParseHexBytes(bn->AsString(), patch_bytes)) {
            err = "Invalid hex in 'bytes'";
            return false;
        }
    } else if (const RivetNode* pn = site.Get("patch")) {
        if (!Scanner::ParseHexBytes(pn->AsString(), patch_bytes)) {
            err = "Invalid hex in 'patch'";
            return false;
        }
    } else {
        err = "Patch site missing 'bytes' (or 'stub_bytes')";
        return false;
    }

    if (!expected_orig.empty() && expected_orig.size() != patch_bytes.size()) {
        err = "Length mismatch between 'orig' and 'bytes'";
        return false;
    }

    std::string site_id = lp.info.name + ":" + site.GetString("id", std::to_string(lp.handles.size()));
    RiftPatchHandle h = RIFT_INVALID_HANDLE;
    RiftResult r = patcher_.Create(
        RIFT_INVALID_HANDLE,
        site_id,
        live_addr,
        expected_orig.empty() ? nullptr : expected_orig.data(),
        patch_bytes.data(),
        patch_bytes.size(),
        enable_now,
        &h);

    if (r != RIFT_OK) {
        switch (r) {
            case RIFT_ERR_BYTES_MISMATCH: err = "Original bytes mismatch at target address (wrong version or conflict)"; break;
            case RIFT_ERR_CONFLICT:       err = "Address range overlaps another active patch"; break;
            case RIFT_ERR_PROTECT_FAILED: err = "VirtualProtect failed at target address"; break;
            default:                      err = "PatchCreate failed with error " + std::to_string(static_cast<int>(r)); break;
        }
        return false;
    }

    lp.handles.push_back(h);
    return true;
}

bool PatchManager::LoadManifestFile(const std::string& path,
                                    const std::unordered_set<std::string>& disabled_names) {
    auto parsed = RivetParser::ParseFile(path);
    if (!parsed.Ok()) {
        logger_.Log(RIFT_LOG_ERROR, "patches", "Parse failed for %s (line %zu): %s",
                    path.c_str(), parsed.error_line, parsed.error.c_str());
        return false;
    }
    return LoadParsedManifest(path, parsed.root.get(), disabled_names);
}

bool PatchManager::LoadParsedManifest(const std::string& path,
                                      const RivetNode* r,
                                      const std::unordered_set<std::string>& disabled_names,
                                      const std::string& forced_error) {
    LoadedPatch lp;
    lp.info.source_path = path;
    lp.info.name = r->GetString("name", std::filesystem::path(path).stem().string());
    lp.info.description = r->GetString("description", r->GetString("why", ""));
    lp.info.author = r->GetString("author", "");
    lp.info.required_manifests = ParseRequiredManifests(r);

    if (!forced_error.empty()) {
        lp.info.enabled = false;
        lp.info.error = forced_error;
        logger_.Log(RIFT_LOG_ERROR, "patches", "Failed to load patch '%s': %s",
                    lp.info.name.c_str(), forced_error.c_str());
        loaded_.push_back(std::move(lp));
        return false;
    }

    bool want_enabled = r->GetBool("enabled", true);
    if (disabled_names.count(lp.info.name)) {
        want_enabled = false;
    }

    if (want_enabled && !lp.info.required_manifests.empty()) {
        std::string missing;
        if (!CheckDependenciesSatisfied(lp.info.required_manifests, missing)) {
            want_enabled = false;
            logger_.Log(RIFT_LOG_WARN, "patches",
                        "Keeping '%s' disabled: required manifest %s",
                        lp.info.name.c_str(), missing.c_str());
        }
    }

    // Support either `patches.arr;` (multi-site) or single `site.obj;` (matching repo manifests).
    std::vector<const RivetNode*> sites;
    if (const RivetNode* arr = r->Get("patches")) {
        for (const auto& child : arr->ordered_children) {
            sites.push_back(child.get());
        }
    } else if (const RivetNode* single = r->Get("site")) {
        sites.push_back(single);
    }

    if (sites.empty()) {
        logger_.Log(RIFT_LOG_WARN, "patches", "Manifest '%s' has no patch sites (skipped)", lp.info.name.c_str());
        return false;
    }

    lp.info.site_count = sites.size();
    std::string err;
    for (const RivetNode* s : sites) {
        if (!ApplySite(lp, *s, want_enabled, err)) {
            // Roll back any partial sites already created for this manifest.
            for (RiftPatchHandle h : lp.handles) patcher_.Remove(h);
            for (void* st : lp.stubs) stubs_.Free(st);
            lp.handles.clear();
            lp.stubs.clear();
            lp.info.enabled = false;
            lp.info.error = err;
            logger_.Log(RIFT_LOG_ERROR, "patches", "Failed to load patch '%s': %s",
                        lp.info.name.c_str(), err.c_str());
            loaded_.push_back(std::move(lp));
            return false;
        }
    }

    lp.info.enabled = want_enabled;
    logger_.Log(RIFT_LOG_INFO, "patches", "Loaded '%s' (%zu site%s) [%s]",
                lp.info.name.c_str(), lp.info.site_count,
                lp.info.site_count == 1 ? "" : "s",
                want_enabled ? "ENABLED" : "disabled");
    loaded_.push_back(std::move(lp));
    return true;
}

void PatchManager::UnloadAll() {
    for (auto& lp : loaded_) {
        for (RiftPatchHandle h : lp.handles) patcher_.Remove(h);
        for (void* s : lp.stubs) stubs_.Free(s);
    }
    loaded_.clear();
}

void PatchManager::ReloadAll(const std::string& dir_path,
                             const std::unordered_set<std::string>& disabled_names) {
    logger_.Log(RIFT_LOG_INFO, "patches", "Reloading .rvt patches from %s", dir_path.c_str());
    UnloadAll();
    LoadDirectory(dir_path, disabled_names);
}

PatchManager::LoadedPatch* PatchManager::FindByName(const std::string& name) {
    for (auto& lp : loaded_) {
        if (lp.info.name == name) return &lp;
    }
    return nullptr;
}

const PatchManager::LoadedPatch* PatchManager::FindByName(const std::string& name) const {
    for (const auto& lp : loaded_) {
        if (lp.info.name == name) return &lp;
    }
    return nullptr;
}

bool PatchManager::CheckDependenciesSatisfied(const std::vector<std::string>& reqs,
                                              std::string& out_missing) const {
    for (const auto& req : reqs) {
        const auto* dep = FindByName(req);
        if (!dep) {
            out_missing = "'" + req + "' is not loaded";
            return false;
        }
        if (!dep->info.error.empty()) {
            out_missing = "'" + req + "' failed to load (" + dep->info.error + ")";
            return false;
        }
        if (!dep->info.enabled) {
            out_missing = "'" + req + "' is disabled";
            return false;
        }
    }
    return true;
}

bool PatchManager::EnableByName(const std::string& name, std::string& out_msg) {
    auto* lp = FindByName(name);
    if (!lp) { out_msg = "Patch not found: " + name; return false; }
    if (!lp->info.error.empty()) { out_msg = "Patch has load error: " + lp->info.error; return false; }
    if (lp->info.enabled) { out_msg = "Patch already enabled: " + name; return true; }

    std::string missing;
    if (!CheckDependenciesSatisfied(lp->info.required_manifests, missing)) {
        out_msg = "Cannot enable '" + name + "': required manifest " + missing;
        logger_.Log(RIFT_LOG_WARN, "patches", "%s", out_msg.c_str());
        return false;
    }

    for (size_t i = 0; i < lp->handles.size(); ++i) {
        RiftResult r = patcher_.Enable(lp->handles[i]);
        if (r != RIFT_OK) {
            for (size_t j = 0; j < i; ++j) patcher_.Disable(lp->handles[j]);
            out_msg = "Failed to enable '" + name + "' (err=" + std::to_string(static_cast<int>(r)) + ")";
            return false;
        }
    }
    lp->info.enabled = true;
    out_msg = "Enabled patch '" + name + "'";
    logger_.Log(RIFT_LOG_INFO, "patches", "%s", out_msg.c_str());
    return true;
}

bool PatchManager::DisableByName(const std::string& name, std::string& out_msg) {
    auto* lp = FindByName(name);
    if (!lp) { out_msg = "Patch not found: " + name; return false; }
    if (!lp->info.enabled) { out_msg = "Patch already disabled: " + name; return true; }

    // Cascade-disable any enabled dependents first so no patch stays active without its dependency.
    std::vector<std::string> cascaded;
    bool progress = true;
    while (progress) {
        progress = false;
        for (auto& other : loaded_) {
            if (!other.info.enabled || &other == lp) continue;
            bool depends_on_disabled = false;
            for (const auto& req : other.info.required_manifests) {
                if (req == name || std::find(cascaded.begin(), cascaded.end(), req) != cascaded.end()) {
                    depends_on_disabled = true;
                    break;
                }
            }
            if (depends_on_disabled) {
                for (RiftPatchHandle h : other.handles) {
                    patcher_.Disable(h);
                }
                other.info.enabled = false;
                cascaded.push_back(other.info.name);
                logger_.Log(RIFT_LOG_INFO, "patches",
                            "Cascade-disabled '%s' (requires '%s')",
                            other.info.name.c_str(), name.c_str());
                progress = true;
            }
        }
    }

    for (RiftPatchHandle h : lp->handles) {
        patcher_.Disable(h);
    }
    lp->info.enabled = false;
    out_msg = "Disabled patch '" + name + "'";
    if (!cascaded.empty()) {
        out_msg += " (also disabled dependent";
        if (cascaded.size() > 1) out_msg += "s";
        out_msg += ": ";
        for (size_t i = 0; i < cascaded.size(); ++i) {
            if (i > 0) out_msg += ", ";
            out_msg += "'" + cascaded[i] + "'";
        }
        out_msg += ")";
    }
    logger_.Log(RIFT_LOG_INFO, "patches", "%s", out_msg.c_str());
    return true;
}

bool PatchManager::ToggleByName(const std::string& name, std::string& out_msg) {
    auto* lp = FindByName(name);
    if (!lp) { out_msg = "Patch not found: " + name; return false; }
    return lp->info.enabled ? DisableByName(name, out_msg) : EnableByName(name, out_msg);
}

std::vector<ManifestPatchInfo> PatchManager::List() const {
    std::vector<ManifestPatchInfo> out;
    out.reserve(loaded_.size());
    for (const auto& lp : loaded_) out.push_back(lp.info);
    return out;
}

} // namespace riftloader
