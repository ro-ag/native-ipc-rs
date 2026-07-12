use super::*;

const PRODUCER: RoleId = RoleId::new(1).unwrap();
const ACK_OWNER: RoleId = RoleId::new(2).unwrap();
const GENERATION: u64 = 9;

fn writer_binding(slot: u32) -> WriterSlotBinding {
    WriterSlotBinding::validated(PRODUCER, GENERATION, 8, slot, 2, ACK_OWNER, slot)
}

const fn route(slot: u32) -> AcknowledgementRoute {
    AcknowledgementRoute::validated(ACK_OWNER, PRODUCER, slot, slot)
}

fn reader_binding(slot: u32) -> ReaderSlotBinding {
    ReaderSlotBinding::validated(PRODUCER, GENERATION, 8, slot, 2)
}

fn observation(sequence: u64) -> SlotObservation {
    SlotObservation {
        role: PRODUCER,
        slot_index: if sequence == 0 {
            0
        } else {
            ((sequence - 1) % 2) as u32
        },
        generation: GENERATION,
        sequence,
        payload_len: 4,
    }
}

#[test]
fn writer_release_publishes_and_reader_acquires() {
    let header = SlotMetadata::new(GENERATION);
    {
        // SAFETY: local test storage has one simulated writer capability.
        let mut writer = unsafe { WriterSlot::bind(&header, writer_binding(0)) }.unwrap();
        writer.prepare_publish(1, None).unwrap().publish(4).unwrap();
    }
    // SAFETY: writer capability was dropped and test performs no mutation.
    let reader = unsafe { ReaderSlot::bind(&header, reader_binding(0)) }.unwrap();
    let observed = reader.observe(1).unwrap();
    assert_eq!(observed, observation(1));
    reader.recheck(observed).unwrap();
}

#[test]
fn reuse_requires_exact_target_generation_and_prior_sequence() {
    let header = SlotMetadata::new(GENERATION);
    // SAFETY: local test storage has one writer capability and no aliases.
    let mut writer = unsafe { WriterSlot::bind(&header, writer_binding(0)) }.unwrap();
    writer.prepare_publish(1, None).unwrap().publish(4).unwrap();
    assert_eq!(
        writer.prepare_publish(3, None).unwrap_err(),
        SlotError::MissingAcknowledgement { sequence: 1 }
    );

    let exact = AcknowledgementObservation {
        owner: ACK_OWNER,
        target: PRODUCER,
        generation: GENERATION,
        slot_index: 0,
        cell_index: 0,
        sequence: 1,
    };
    writer
        .prepare_publish(3, Some(exact))
        .unwrap()
        .publish(2)
        .unwrap();

    let lagging = AcknowledgementObservation {
        sequence: 0,
        ..exact
    };
    assert!(matches!(
        writer.prepare_publish(5, Some(lagging)),
        Err(SlotError::LaggingAcknowledgement { .. })
    ));
    let future = AcknowledgementObservation {
        sequence: 4,
        ..exact
    };
    assert!(matches!(
        writer.prepare_publish(5, Some(future)),
        Err(SlotError::FutureAcknowledgement { .. })
    ));
    let wrong_target = AcknowledgementObservation {
        target: ACK_OWNER,
        sequence: 3,
        ..exact
    };
    assert_eq!(
        writer.prepare_publish(5, Some(wrong_target)).unwrap_err(),
        SlotError::WrongAcknowledgementTarget
    );
    let wrong_owner = AcknowledgementObservation {
        owner: PRODUCER,
        sequence: 3,
        ..exact
    };
    assert_eq!(
        writer.prepare_publish(5, Some(wrong_owner)).unwrap_err(),
        SlotError::WrongAcknowledgementOwner
    );
    let stale = AcknowledgementObservation {
        generation: GENERATION - 1,
        sequence: 3,
        ..exact
    };
    assert_eq!(
        writer.prepare_publish(5, Some(stale)).unwrap_err(),
        SlotError::StaleAcknowledgementGeneration
    );
}

#[test]
fn acknowledgement_capabilities_are_split_and_monotonic() {
    let cell = AcknowledgementCell::new();
    let writer_binding = AcknowledgementWriterBinding::validated(route(0), GENERATION);
    {
        // SAFETY: local test storage has one simulated acknowledgement writer.
        let mut writer = unsafe { AcknowledgementWriter::bind(&cell, writer_binding) };
        writer.acknowledge(observation(1)).unwrap();
        writer.acknowledge(observation(1)).unwrap();
        writer.acknowledge(observation(3)).unwrap();
        assert_eq!(
            writer.acknowledge(observation(1)).unwrap_err(),
            AcknowledgementError::NonMonotonic {
                current: 3,
                next: 1
            }
        );
        assert!(matches!(
            writer.acknowledge(observation(0)),
            Err(AcknowledgementError::UnpublishedSequence)
        ));
    }
    let reader_binding = AcknowledgementReaderBinding::validated(route(0), GENERATION);
    // SAFETY: simulated writer was dropped; storage is immutable here.
    let reader = unsafe { AcknowledgementReader::bind(&cell, reader_binding) };
    let observed = reader.observe();
    assert_eq!(observed.owner(), ACK_OWNER);
    assert_eq!(observed.target(), PRODUCER);
    assert_eq!(observed.generation(), GENERATION);
    assert_eq!(observed.sequence(), 3);

    let mut terminal = AcknowledgementCell::new();
    *terminal.sequence.get_mut() = u64::MAX;
    let mut writer = unsafe {
        AcknowledgementWriter::bind(
            &terminal,
            AcknowledgementWriterBinding::validated(route(0), GENERATION),
        )
    };
    let maximum = SlotObservation {
        sequence: u64::MAX,
        slot_index: 0,
        ..observation(1)
    };
    writer.acknowledge(maximum).unwrap();
}

#[test]
fn two_slot_routes_complete_multiple_rotations() {
    let headers = [SlotMetadata::new(GENERATION), SlotMetadata::new(GENERATION)];
    let cells = [AcknowledgementCell::new(), AcknowledgementCell::new()];
    let mut acknowledgements = [None, None];

    for sequence in 1..=6 {
        let slot = ((sequence - 1) % 2) as usize;
        let mut writer =
            unsafe { WriterSlot::bind(&headers[slot], writer_binding(slot as u32)) }.unwrap();
        writer
            .prepare_publish(sequence, acknowledgements[slot])
            .unwrap()
            .publish(4)
            .unwrap();
        let reader =
            unsafe { ReaderSlot::bind(&headers[slot], reader_binding(slot as u32)) }.unwrap();
        let observed = reader.observe(sequence).unwrap();
        reader.recheck(observed).unwrap();
        let binding = AcknowledgementWriterBinding::validated(route(slot as u32), GENERATION);
        let mut acknowledgement_writer =
            unsafe { AcknowledgementWriter::bind(&cells[slot], binding) };
        acknowledgement_writer.acknowledge(observed).unwrap();
        let binding = AcknowledgementReaderBinding::validated(route(slot as u32), GENERATION);
        let acknowledgement_reader = unsafe { AcknowledgementReader::bind(&cells[slot], binding) };
        acknowledgements[slot] = Some(acknowledgement_reader.observe());
    }

    let mut slot_zero = unsafe { WriterSlot::bind(&headers[0], writer_binding(0)) }.unwrap();
    let wrong_cell = AcknowledgementObservation {
        cell_index: 1,
        sequence: 5,
        ..acknowledgements[0].unwrap()
    };
    assert_eq!(
        slot_zero.prepare_publish(7, Some(wrong_cell)).unwrap_err(),
        SlotError::WrongAcknowledgementCell
    );
    let wrong_slot = AcknowledgementObservation {
        slot_index: 1,
        cell_index: 0,
        sequence: 5,
        ..acknowledgements[0].unwrap()
    };
    assert_eq!(
        slot_zero.prepare_publish(7, Some(wrong_slot)).unwrap_err(),
        SlotError::WrongAcknowledgementSlot
    );
}

#[test]
fn production_interleaving_model_accepts_only_exact_prior_ack() {
    for current in [1_u64, 3, 5] {
        for acknowledged in 0..=current + 1 {
            let mut header = SlotMetadata::new(GENERATION);
            *header.published_sequence.get_mut() = current;
            let mut writer = unsafe { WriterSlot::bind(&header, writer_binding(0)) }.unwrap();
            let result = writer.prepare_publish(
                current + 2,
                Some(AcknowledgementObservation {
                    owner: ACK_OWNER,
                    target: PRODUCER,
                    generation: GENERATION,
                    slot_index: 0,
                    cell_index: 0,
                    sequence: acknowledged,
                }),
            );
            assert_eq!(result.is_ok(), acknowledged == current);
        }
    }
}

#[test]
fn recheck_detects_length_change_but_does_not_claim_payload_integrity() {
    let header = SlotMetadata::new(GENERATION);
    {
        let mut writer = unsafe { WriterSlot::bind(&header, writer_binding(0)) }.unwrap();
        writer.prepare_publish(1, None).unwrap().publish(4).unwrap();
    }
    let reader = unsafe { ReaderSlot::bind(&header, reader_binding(0)) }.unwrap();
    let observed = reader.observe(1).unwrap();
    header.payload_len.store(5, Ordering::Relaxed);
    assert_eq!(
        reader.recheck(observed).unwrap_err(),
        SlotError::ChangedPayloadLength {
            expected: 4,
            actual: 5
        }
    );
}

#[test]
fn rejects_wrong_slot_zero_sequence_oversize_and_wrap() {
    let header = SlotMetadata::new(GENERATION);
    // SAFETY: local test storage has one writer capability.
    let mut writer = unsafe { WriterSlot::bind(&header, writer_binding(1)) }.unwrap();
    assert_eq!(
        writer.prepare_publish(0, None).unwrap_err(),
        SlotError::UnpublishedSequence
    );
    assert!(matches!(
        writer.prepare_publish(1, None),
        Err(SlotError::WrongSlot { .. })
    ));
    assert!(matches!(
        writer.prepare_publish(2, None).unwrap().publish(9),
        Err(SlotError::PayloadTooLarge { .. })
    ));

    let mut wrapped = SlotMetadata::new(GENERATION);
    *wrapped.published_sequence.get_mut() = u64::MAX;
    // SAFETY: separate local storage has one writer capability.
    let mut writer = unsafe { WriterSlot::bind(&wrapped, writer_binding(0)) }.unwrap();
    assert_eq!(
        writer
            .prepare_publish(
                u64::MAX,
                Some(AcknowledgementObservation {
                    owner: ACK_OWNER,
                    target: PRODUCER,
                    generation: GENERATION,
                    slot_index: 0,
                    cell_index: 0,
                    sequence: u64::MAX,
                })
            )
            .unwrap_err(),
        SlotError::SequenceWrap
    );
}
