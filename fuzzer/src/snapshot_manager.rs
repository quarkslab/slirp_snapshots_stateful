// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

use hashbrown::HashMap;
use libafl_qemu::{
    GuestAddr, IsSnapshotManager, QemuSnapshotCheckResult, SnapshotId,
    modules::{
        SnapshotModule,
        snapshot::{IntervalSnapshotFilters, MappingInfo, SnapshotAccessInfo, SnapshotPageInfo},
    },
};
use std::collections::VecDeque;

use crate::libslirp;
use crate::utils::{get_observer_module_mut, get_snapshot_module_mut};

#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    base_id: Option<SnapshotId>,
    content: SnapshotContent,
    paths: HashMap<SnapshotId, VecDeque<SnapshotId>>,
    child_dirty_hash: Vec<u64>,
}

// TODO find a good name
#[derive(Debug, Clone)]
pub struct IncrementalSnapshotManager {
    snapshots: HashMap<SnapshotId, SnapshotInfo>,
    pub current_id: Option<SnapshotId>,
    pub parent_id: Option<SnapshotId>,
}

impl IncrementalSnapshotManager {
    pub fn new() -> Self {
        Self {
            snapshots: HashMap::new(),
            current_id: None,
            parent_id: None,
        }
    }
}

impl IncrementalSnapshotManager {
    fn restore_internal(
        &mut self,
        qemu: libafl_qemu::Qemu,
        snapshot_id: &libafl_qemu::SnapshotId,
        snapshot_module: &mut SnapshotModule,
    ) -> Result<(), libafl_qemu::SnapshotManagerError> {
        log::debug!("restoring {:?} from {:?}", snapshot_id, self.current_id);

        let cur_id = &self.current_id.unwrap();
        let current_snap_base_id = match self.snapshots.get(cur_id) {
            Some(info) => info.base_id,
            None => {
                log::error!(
                    "{:#?}",
                    self.snapshots
                        .get(&SnapshotId::new_from_id(0))
                        .unwrap()
                        .paths
                );
                panic!(
                    "current snapshot {:?} was not found in the snapshots hashmap",
                    cur_id
                );
            }
        };

        let current_snap_new_maps = self
            .snapshots
            .get(&self.current_id.unwrap())
            .unwrap()
            .content
            .new_maps
            .clone();

        let target_snap_info = self.snapshots.get(snapshot_id).unwrap();
        let target_snap_base_id = target_snap_info.base_id;

        // Restore the target snapshot infos in the snapshot module.
        snapshot_module.brk = target_snap_info.content.brk;
        snapshot_module.initial_brk = target_snap_info.content.initial_brk;
        snapshot_module.interval_filter = target_snap_info.content.interval_filter.clone();
        snapshot_module.maps = target_snap_info.content.maps.clone();
        snapshot_module.mmap_limit = target_snap_info.content.mmap_limit;
        snapshot_module.mmap_start = target_snap_info.content.mmap_start;
        snapshot_module.pages = target_snap_info.content.pages.clone();
        snapshot_module.new_maps = current_snap_new_maps.into();

        // If the snapshot we restore is the parent we use the diff from the current snapshot.
        // Otherwise we are restoring a child so we need to load the diff leading to the child.
        if current_snap_base_id == Some(*snapshot_id) {
            let current_snap_accesses = self
                .snapshots
                .get(&self.current_id.unwrap())
                .unwrap()
                .content
                .accesses
                .clone();
            let accesses = snapshot_module.accesses.get().unwrap().get();
            unsafe {
                (*accesses).access_cache = current_snap_accesses.access_cache;
                (*accesses).access_cache_idx = current_snap_accesses.access_cache_idx;
                (*accesses).dirty = current_snap_accesses.dirty.clone();
            }
        } else if target_snap_base_id == self.current_id {
            let target_snap_accesses = target_snap_info.content.accesses.clone();
            let accesses = snapshot_module.accesses.get().unwrap().get();
            unsafe {
                (*accesses).access_cache = target_snap_accesses.access_cache;
                (*accesses).access_cache_idx = target_snap_accesses.access_cache_idx;
                (*accesses).dirty = target_snap_accesses.dirty.clone();
            }
        }

        snapshot_module.reset(qemu);
        self.parent_id = target_snap_base_id;
        self.current_id = Some(*snapshot_id);

        Ok(())
    }
}

impl IsSnapshotManager for IncrementalSnapshotManager {
    fn save(&mut self, qemu: libafl_qemu::Qemu) -> libafl_qemu::SnapshotId {
        let snap = get_snapshot_module_mut();

        let diff = if let Some(current_id) = self.current_id {
            let accesses = snap.accesses.get().unwrap().get();
            let access_cache = unsafe { (*accesses).access_cache };
            let access_cache_idx = unsafe { (*accesses).access_cache_idx };
            let dirty = unsafe { (*accesses).dirty.clone() };

            let snap = self.snapshots.get_mut(&current_id).unwrap();

            let hash = libslirp::utils::hash_state(&qemu);

            if snap.child_dirty_hash.contains(&hash) {
                return current_id;
            } else {
                snap.child_dirty_hash.push(hash);
            }

            Some(SnapshotAccessInfo {
                access_cache,
                access_cache_idx,
                dirty,
            })
        } else {
            None
        };

        snap.snapshot(qemu);
        let mut content = SnapshotContent::new();
        content.brk = snap.brk;
        content.initial_brk = snap.initial_brk;
        content.interval_filter = snap.interval_filter.clone();
        content.maps = snap.maps.clone();
        content.mmap_limit = snap.mmap_limit;
        content.mmap_start = snap.mmap_start;
        content.new_maps = snap.new_maps.get_mut().unwrap().clone();
        content.pages = snap.pages.clone();
        if let Some(diff) = diff {
            content.accesses = diff;
        }

        let snap_id = SnapshotId::gen_unique_id();
        log::debug!("Generating {:?} from {:?}", snap_id, self.current_id);

        let paths = if let Some(parent_id) = self.current_id {
            // Add the parent as the first node to traverse to reach all other nodes
            let mut parent_paths = self.snapshots.get(&parent_id).unwrap().paths.clone();
            for entry in parent_paths.iter_mut() {
                entry.1.push_front(parent_id);
            }

            // Add the new node as a target to all other nodes, taking the parent as a base
            for (_tid, snapshot_info) in &mut self.snapshots {
                let mut parent_path = snapshot_info.paths.get(&parent_id).unwrap().clone();
                parent_path.push_back(snap_id);
                snapshot_info.paths.insert(snap_id, parent_path);
            }
            parent_paths.insert(snap_id, VecDeque::new());

            parent_paths
        } else {
            let mut paths = HashMap::new();
            paths.insert(snap_id, VecDeque::new());
            paths
        };

        let info = SnapshotInfo {
            content,
            base_id: self.current_id,
            paths,
            child_dirty_hash: Vec::new(),
        };

        self.parent_id = self.current_id;
        self.current_id = Some(snap_id);
        self.snapshots.insert(snap_id, info);

        let obs = get_observer_module_mut();
        *obs.snapshot_id_mut() = self.current_id;
        *obs.snapshot_parent_id_mut() = self.parent_id;

        snap_id
    }

    fn restore(
        &mut self,
        qemu: libafl_qemu::Qemu,
        snapshot_id: &libafl_qemu::SnapshotId,
    ) -> Result<(), libafl_qemu::SnapshotManagerError> {
        let current_snapshot = get_snapshot_module_mut();

        current_snapshot.reset(qemu);
        let current_id = self.current_id.unwrap();
        if *snapshot_id != current_id {
            let path = self
                .snapshots
                .get(&current_id)
                .expect("failed to fetch the current snapshot during restore")
                .paths
                .get(snapshot_id)
                .expect("paths doesn't contain the target snapshot")
                .clone();
            for node in path {
                let _ = self.restore_internal(qemu, &node, current_snapshot);
            }
        }

        Ok(())
    }

    fn do_check(
        &self,
        qemu: libafl_qemu::Qemu,
        _reference_snapshot_id: &libafl_qemu::SnapshotId,
    ) -> Result<libafl_qemu::QemuSnapshotCheckResult, libafl_qemu::SnapshotManagerError> {
        let current_snapshot = get_snapshot_module_mut();
        current_snapshot.check_snapshot(qemu);
        Ok(QemuSnapshotCheckResult::default())
    }
}

#[derive(Clone)]
pub struct SnapshotContent {
    pub maps: MappingInfo,
    pub accesses: SnapshotAccessInfo,
    pub new_maps: MappingInfo,
    pub pages: HashMap<GuestAddr, SnapshotPageInfo>,
    pub initial_brk: GuestAddr,
    pub brk: GuestAddr,
    pub mmap_start: GuestAddr,
    pub mmap_limit: usize,
    pub interval_filter: IntervalSnapshotFilters,
}

impl core::fmt::Debug for SnapshotContent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SnapshotContent")
            .field("new_maps", &self.new_maps)
            .field("pages", &self.pages)
            .field("brk", &self.brk)
            .field("mmap_start", &self.mmap_start)
            .field("mmap_limit", &self.mmap_limit)
            .finish_non_exhaustive()
    }
}

impl SnapshotContent {
    pub fn new() -> Self {
        Self {
            maps: MappingInfo::default(),
            accesses: SnapshotAccessInfo::default(),
            new_maps: MappingInfo::default(),
            pages: HashMap::default(),
            initial_brk: 0,
            brk: 0,
            mmap_start: 0,
            mmap_limit: 0,
            interval_filter: IntervalSnapshotFilters::new(),
        }
    }
}
