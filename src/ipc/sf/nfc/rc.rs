pub const RESULT_MODULE: u32 = 161;

result_define_group!(RESULT_MODULE => {
    DeviceNotFound: 64,
    WrongArgument: 65,
    WrongDeviceState: 73,
    NFCDisabled: 80,
    TagNotFound: 97,
    MifareAccessError: 288
});
