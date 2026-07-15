use std::io::{Read, Write};
use std::time::Duration;

use static_assertions::assert_not_impl_any;

use super::*;

assert_not_impl_any!(BrokerTraceReportReceiver: Clone, Copy);
assert_not_impl_any!(AuthenticatedBrokerTraceReport: Clone, Copy);
assert_not_impl_any!(BrokerResumeSender: Clone, Copy);

fn binding() -> BrokerTraceReportBinding {
    BrokerTraceReportBinding::new(
        SupervisorDeadline::from_wire(u64::MAX - 1),
        91,
        1,
        501,
        20,
        [1; 32],
        [2; 32],
        [3; 32],
        [4; 32],
        [5; 32],
    )
}

#[test]
fn trace_report_codec_is_fixed_and_rejects_every_mutation() {
    let exact = encode_broker_trace_report(binding()).unwrap();
    assert_eq!(exact.len(), BROKER_TRACE_REPORT_BYTES);
    assert_eq!(
        ReceivedBrokerTraceReport::decode(&exact).unwrap(),
        binding()
    );

    for offset in [0, 8, 10, 12, 16, 24, 32, 40, 44, 48, 80, 112, 144, 176, 208] {
        let mut mutation = exact;
        mutation[offset] ^= 1;
        assert_ne!(
            ReceivedBrokerTraceReport::decode(&mutation),
            Ok(binding()),
            "offset {offset}"
        );
    }
}

#[test]
fn receiver_requires_exact_frame_eof_and_expected_binding() {
    let (mut writer, reader) = UnixStream::pair().unwrap();
    let mut receipt =
        BrokerTraceReportReceiver::new(reader, binding(), Instant::now() + Duration::from_secs(2))
            .unwrap();
    let exact = encode_broker_trace_report(binding()).unwrap();
    writer.write_all(&exact[..100]).unwrap();
    assert!(receipt.poll().unwrap().is_none());
    writer.write_all(&exact[100..]).unwrap();
    assert!(receipt.poll().unwrap().is_none());
    finish_broker_trace_report(&writer).unwrap();
    assert!(receipt.poll().unwrap().is_some());

    for bytes in [exact[..exact.len() - 1].to_vec(), {
        let mut extended = exact.to_vec();
        extended.push(1);
        extended
    }] {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        let mut receipt = BrokerTraceReportReceiver::new(
            reader,
            binding(),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        writer.write_all(&bytes).unwrap();
        finish_broker_trace_report(&writer).unwrap();
        assert!(receipt.poll().is_err());
    }

    let mut wrong = binding();
    wrong.session[31] ^= 1;
    let (mut writer, reader) = UnixStream::pair().unwrap();
    let mut receipt =
        BrokerTraceReportReceiver::new(reader, wrong, Instant::now() + Duration::from_secs(2))
            .unwrap();
    writer.write_all(&exact).unwrap();
    finish_broker_trace_report(&writer).unwrap();
    assert!(matches!(
        receipt.poll(),
        Err(BrokerTraceReportError::Binding)
    ));

    let (_writer, reader) = UnixStream::pair().unwrap();
    assert!(matches!(
        BrokerTraceReportReceiver::new(reader, binding(), Instant::now()),
        Err(BrokerTraceReportError::DeadlineExpired)
    ));
}

#[test]
fn reverse_resume_commit_is_exact_one_byte_plus_eof() {
    let (service, mut broker) = UnixStream::pair().unwrap();
    service.set_nonblocking(true).unwrap();
    let mut resume_sender = BrokerResumeSender {
        stream: Some(service),
    };
    resume_sender.commit_after_ready().unwrap();
    let mut resume = [0_u8; 2];
    assert_eq!(broker.read(&mut resume).unwrap(), 1);
    assert_eq!(resume[0], BROKER_RESUME_BYTE[0]);
    assert_eq!(broker.read(&mut resume).unwrap(), 0);
}
