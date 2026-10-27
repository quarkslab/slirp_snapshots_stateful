// SPDX-FileCopyrightText: 2026 Quarkslab
//
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

use lain::traits::Mutatable;
use libafl::{
    mutators::{MutationResult, Mutator},
    state::{HasCurrentTestcase, HasRand},
};
use libafl_bolts::{Named, rands::StdRand};

use crate::network_targets_utils::inputs::Packet;

pub struct PacketMutator {
    pub lain: lain::mutator::Mutator<StdRand>,
}

impl PacketMutator {
    pub fn new() -> Self {
        Self {
            lain: lain::mutator::Mutator::new(StdRand::new()),
        }
    }
}

impl Named for PacketMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("packet_mutator");
        &NAME
    }
}

impl<S> Mutator<Packet, S> for PacketMutator
where
    S: HasRand + HasCurrentTestcase<Packet>,
{
    fn mutate(
        &mut self,
        _state: &mut S,
        input: &mut Packet,
    ) -> Result<libafl::mutators::MutationResult, libafl::Error> {
        match &mut input.packet {
            crate::network_targets_utils::inputs::PacketType::Ip4(ipv4) => {
                ipv4.params.mutate(&mut self.lain, None);
                ipv4.payload.mutate(&mut self.lain, None);
            }
            crate::network_targets_utils::inputs::PacketType::Ip6(ipv6) => {
                ipv6.params.mutate(&mut self.lain, None);
                ipv6.payload.mutate(&mut self.lain, None);
            }
        }

        Ok(MutationResult::Mutated)
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _new_corpus_id: Option<libafl::corpus::CorpusId>,
    ) -> Result<(), libafl::Error> {
        Ok(())
    }
}
