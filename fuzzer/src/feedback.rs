// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

use std::{borrow::Cow, marker::PhantomData};

use libafl::{
    HasMetadata,
    events::{Event, EventFirer, EventWithStats, ExecStats},
    feedbacks::{Feedback, StateInitializer},
    inputs::Input,
    monitors::stats::{AggregatorOps, UserStats},
};
use libafl_bolts::{Error, Named, current_time, impl_serdeany, tuples::MatchNameRef};
use libafl_qemu::SnapshotId;
use serde::{Deserialize, Serialize};

use crate::network_targets_utils;
use crate::utils::get_observer_module_mut;

static SNAPSHOTS_STRING: Cow<'static, str> = Cow::Borrowed("snapshots");

impl_serdeany!(SnapshotMetadata);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SnapshotMetadata {
    associated_snapshot: SnapshotId,
    parent_snapshot: Option<SnapshotId>,
    gen_bytes: Vec<u8>,
}

impl SnapshotMetadata {
    #[allow(unused)]
    pub fn new(id: SnapshotId, parent_id: Option<SnapshotId>, gen_bytes: &[u8]) -> Self {
        Self {
            associated_snapshot: id,
            parent_snapshot: parent_id,
            gen_bytes: Vec::from(gen_bytes),
        }
    }

    #[allow(unused)]
    pub fn snapshot_id(&self) -> SnapshotId {
        self.associated_snapshot
    }

    #[allow(unused)]
    pub fn snapshot_parent_id(&self) -> Option<SnapshotId> {
        self.parent_snapshot
    }

    #[allow(unused)]
    pub fn snapshot_gen_bytes(&self) -> &[u8] {
        &self.gen_bytes
    }
}

pub struct StateChangedFeedback {}

impl StateChangedFeedback {
    pub fn new() -> Self {
        Self {}
    }
}

impl<S> StateInitializer<S> for StateChangedFeedback
where
    S: HasMetadata,
{
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for StateChangedFeedback {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("state_changed_feedback");
        &NAME
    }
}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for StateChangedFeedback
where
    EM: EventFirer<I, S>,
    S: HasMetadata,
    OT: MatchNameRef,
    I: Input,
{
    fn is_interesting(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &libafl::executors::ExitKind,
    ) -> Result<bool, libafl::Error> {
        let obs = get_observer_module_mut();
        let state_changed = *obs.state_changed();
        if state_changed {
            let snap_id = obs.snapshot_id().unwrap();
            manager.fire(
                state,
                EventWithStats::new(
                    Event::UpdateUserStats {
                        name: SNAPSHOTS_STRING.clone(),
                        value: UserStats::new(
                            libafl::monitors::stats::UserStatsValue::Number(snap_id.inner()),
                            AggregatorOps::Max,
                        ),
                        phantom: PhantomData,
                    },
                    ExecStats::new(current_time(), snap_id.inner()),
                ),
            )?;
        }
        Ok(state_changed)
    }

    fn append_metadata(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut libafl::corpus::Testcase<I>,
    ) -> Result<(), libafl::Error> {
        let state_obs = get_observer_module_mut();
        let snap_id = state_obs.snapshot_id().unwrap();
        let parent_id = state_obs.snapshot_parent_id();
        let gen_bytes = state_obs.snapshot_gen_bytes();
        let snapshot_meta = SnapshotMetadata::new(snap_id, *parent_id, gen_bytes);

        log::debug!(
            "adding to {:?} -- {:?}",
            testcase.filename(),
            testcase.corpus_id()
        );
        log::debug!("{:?}", snapshot_meta);
        testcase.add_metadata(snapshot_meta);

        network_targets_utils::utils::add_tcp_metadata(testcase);

        Ok(())
    }
}
