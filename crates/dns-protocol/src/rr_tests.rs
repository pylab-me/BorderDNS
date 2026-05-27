use super::*;

#[test]
fn test_a_record_roundtrip() {
    let rr = ResourceRecord {
        name: DomainName::from_str("example.com").unwrap(),
        rr_type: RecordType::A,
        class: RecordClass::In,
        ttl: 300,
        rdata: RData::A(Ipv4Addr::new(93, 184, 216, 34)),
    };

    let mut writer = WireWriter::new();
    rr.write_to(&mut writer);
    let wire = writer.into_bytes();

    let mut reader = WireReader::new(&wire);
    let decoded = ResourceRecord::read(&mut reader, &wire).unwrap();
    assert_eq!(decoded.name, rr.name);
    assert_eq!(decoded.rr_type, RecordType::A);
    assert_eq!(decoded.ttl, 300);
    assert_eq!(decoded.rdata, RData::A(Ipv4Addr::new(93, 184, 216, 34)));
}

#[test]
fn test_aaaa_record_roundtrip() {
    let rr = ResourceRecord {
        name: DomainName::from_str("example.com").unwrap(),
        rr_type: RecordType::AAAA,
        class: RecordClass::In,
        ttl: 300,
        rdata: RData::AAAA(Ipv6Addr::new(0x2606, 0x2800, 0x0220, 0, 0, 0, 0, 0x0001)),
    };

    let mut writer = WireWriter::new();
    rr.write_to(&mut writer);
    let wire = writer.into_bytes();

    let mut reader = WireReader::new(&wire);
    let decoded = ResourceRecord::read(&mut reader, &wire).unwrap();
    assert_eq!(decoded.rdata, rr.rdata);
}

#[test]
fn test_cname_record_roundtrip() {
    let rr = ResourceRecord {
        name: DomainName::from_str("www.example.com").unwrap(),
        rr_type: RecordType::CNAME,
        class: RecordClass::In,
        ttl: 600,
        rdata: RData::CNAME(DomainName::from_str("example.com").unwrap()),
    };

    let mut writer = WireWriter::new();
    rr.write_to(&mut writer);
    let wire = writer.into_bytes();

    let mut reader = WireReader::new(&wire);
    let decoded = ResourceRecord::read(&mut reader, &wire).unwrap();
    assert_eq!(decoded.rdata, rr.rdata);
}

#[test]
fn test_mx_record_roundtrip() {
    let rr = ResourceRecord {
        name: DomainName::from_str("example.com").unwrap(),
        rr_type: RecordType::MX,
        class: RecordClass::In,
        ttl: 3600,
        rdata: RData::MX(MxRecord {
            preference: 10,
            exchange: DomainName::from_str("mail.example.com").unwrap(),
        }),
    };

    let mut writer = WireWriter::new();
    rr.write_to(&mut writer);
    let wire = writer.into_bytes();

    let mut reader = WireReader::new(&wire);
    let decoded = ResourceRecord::read(&mut reader, &wire).unwrap();
    assert_eq!(decoded.rdata, rr.rdata);
}

#[test]
fn test_soa_record_roundtrip() {
    let rr = ResourceRecord {
        name: DomainName::from_str("example.com").unwrap(),
        rr_type: RecordType::SOA,
        class: RecordClass::In,
        ttl: 0,
        rdata: RData::SOA(SoaRecord {
            mname: DomainName::from_str("ns1.example.com").unwrap(),
            rname: DomainName::from_str("admin.example.com").unwrap(),
            serial: 2024010101,
            refresh: 3600,
            retry: 900,
            expire: 1209600,
            minimum: 86400,
        }),
    };

    let mut writer = WireWriter::new();
    rr.write_to(&mut writer);
    let wire = writer.into_bytes();

    let mut reader = WireReader::new(&wire);
    let decoded = ResourceRecord::read(&mut reader, &wire).unwrap();
    assert_eq!(decoded.rdata, rr.rdata);
}

#[test]
fn test_txt_record_roundtrip() {
    let rr = ResourceRecord {
        name: DomainName::from_str("example.com").unwrap(),
        rr_type: RecordType::TXT,
        class: RecordClass::In,
        ttl: 300,
        rdata: RData::TXT(vec![b"v=spf1 include:_spf.example.com ~all".to_vec()]),
    };

    let mut writer = WireWriter::new();
    rr.write_to(&mut writer);
    let wire = writer.into_bytes();

    let mut reader = WireReader::new(&wire);
    let decoded = ResourceRecord::read(&mut reader, &wire).unwrap();
    assert_eq!(decoded.rdata, rr.rdata);
}

#[test]
fn test_unknown_rr_passthrough() {
    let rr = ResourceRecord {
        name: DomainName::from_str("example.com").unwrap(),
        rr_type: RecordType::Unknown(99),
        class: RecordClass::In,
        ttl: 300,
        rdata: RData::Unknown {
            rr_type: 99,
            data: vec![0x01, 0x02, 0x03, 0x04],
        },
    };

    let mut writer = WireWriter::new();
    rr.write_to(&mut writer);
    let wire = writer.into_bytes();

    let mut reader = WireReader::new(&wire);
    let decoded = ResourceRecord::read(&mut reader, &wire).unwrap();
    assert_eq!(decoded.rr_type, RecordType::Unknown(99));
    if let RData::Unknown { rr_type, data } = decoded.rdata {
        assert_eq!(rr_type, 99);
        assert_eq!(data, vec![0x01, 0x02, 0x03, 0x04]);
    } else {
        panic!("Expected Unknown RData");
    }
}

#[test]
fn test_opt_record_roundtrip() {
    let rr = ResourceRecord {
        name: DomainName::root(),
        rr_type: RecordType::OPT,
        class: RecordClass::Unknown(1232),
        ttl: 0,
        rdata: RData::OPT(OptRecord {
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            do_flag: true,
            options: vec![],
        }),
    };

    let mut writer = WireWriter::new();
    rr.write_to(&mut writer);
    let wire = writer.into_bytes();

    let mut reader = WireReader::new(&wire);
    let decoded = ResourceRecord::read(&mut reader, &wire).unwrap();
    if let RData::OPT(opt) = &decoded.rdata {
        assert_eq!(opt.udp_payload_size, 1232);
        assert!(opt.do_flag);
    } else {
        panic!("Expected OPT RData");
    }
}

#[test]
fn test_ptr_record_roundtrip() {
    let rr = ResourceRecord {
        name: DomainName::from_str("34.216.184.93.in-addr.arpa").unwrap(),
        rr_type: RecordType::PTR,
        class: RecordClass::In,
        ttl: 300,
        rdata: RData::PTR(DomainName::from_str("example.com").unwrap()),
    };

    let mut writer = WireWriter::new();
    rr.write_to(&mut writer);
    let wire = writer.into_bytes();

    let mut reader = WireReader::new(&wire);
    let decoded = ResourceRecord::read(&mut reader, &wire).unwrap();
    assert_eq!(decoded.rdata, rr.rdata);
}

#[test]
fn test_ns_record_roundtrip() {
    let rr = ResourceRecord {
        name: DomainName::from_str("example.com").unwrap(),
        rr_type: RecordType::NS,
        class: RecordClass::In,
        ttl: 86400,
        rdata: RData::NS(DomainName::from_str("ns1.example.com").unwrap()),
    };

    let mut writer = WireWriter::new();
    rr.write_to(&mut writer);
    let wire = writer.into_bytes();

    let mut reader = WireReader::new(&wire);
    let decoded = ResourceRecord::read(&mut reader, &wire).unwrap();
    assert_eq!(decoded.rdata, rr.rdata);
}

#[test]
fn test_srv_record_roundtrip() {
    let rr = ResourceRecord {
        name: DomainName::from_str("_sip._tcp.example.com").unwrap(),
        rr_type: RecordType::SRV,
        class: RecordClass::In,
        ttl: 300,
        rdata: RData::SRV(SrvRecord {
            priority: 10,
            weight: 20,
            port: 5060,
            target: DomainName::from_str("sip.example.com").unwrap(),
        }),
    };

    let mut writer = WireWriter::new();
    rr.write_to(&mut writer);
    let wire = writer.into_bytes();

    let mut reader = WireReader::new(&wire);
    let decoded = ResourceRecord::read(&mut reader, &wire).unwrap();
    assert_eq!(decoded.rdata, rr.rdata);
}
