#![no_std]
/**
 * @file application_processor.c
 * @author Jacob Doll, devilmanCr0
 * @brief eCTF AP Design Implementation in Mf Rust
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

use core::panic::PanicInfo;
use core::mem;

const MAX_I2C_MESSAGE_LEN: usize = 256;
const HASH_LENGTH        : usize = 32;
const PIN_LENGTH         : usize = 64;
const TOKEN_LENGTH       : usize = 64;

#[allow(non_camel_case_types)]
enum component_cmd_t {
    COMPONENT_CMD_NONE = 0,
    COMPONENT_CMD_SCAN = 1,
    COMPONENT_CMD_VALIDATE = 2,
    COMPONENT_CMD_BOOT = 3,
    COMPONENT_CMD_ATTEST = 4,
}

#[derive(PartialEq)]
#[allow(non_camel_case_types)]
enum return_codes {
        SUCCESS_RETURN = 0,
        ERROR_RETURN = -1,
}


// Make sure to extract C's value of MAX_I2C_Message_LEN later
#[repr(C)]
pub struct command_message {
        pub opcode: u8,
        pub params: [u8; MAX_I2C_MESSAGE_LEN-1],
}

#[allow(non_camel_case_types)]
type nonce_t = u64; // 64 bit

#[allow(non_camel_case_types)]
type i2c_addr_t = u8;

#[repr(C)]
pub struct validate_message {
      pub component_id: u32,
      pub nonce1: nonce_t,
      pub nonce2: nonce_t,
}

#[repr(C)]
pub struct plain_nonce {
       pub rand: i32,
       pub timestamp: i32,
}

#[repr(C)]
pub struct flash_entry {
       pub flash_magic: u32, 
       pub component_cnt: u32,
       pub component_ids: [u32; 32]
}


#[panic_handler]
fn panik(_panic_info: &PanicInfo) -> ! {
        unsafe { LED_Off(1) }; // LED_GREEN
        loop {}
}

extern {
        fn generate_nonce() -> nonce_t; 
        fn printf(format: *const u8, ...) -> ();
        
        fn LED_Off(idx: u32) -> (); // A MAX78000 msdk-specific function
          
        fn process_boot(expected_nonce2: nonce_t, command: *const command_message) -> ();
        fn process_scan() -> ();
        fn process_validate(nonce2: nonce_t, command: *const command_message) -> ();
        fn process_attest() -> ();

        static mut receive_buffer: [u8; MAX_I2C_MESSAGE_LEN];
        static mut transmit_buffer: [u8; MAX_I2C_MESSAGE_LEN];

}

#[no_mangle]
pub extern "C" fn component_process_cmd() -> () {
    unsafe {
            const command: &command_message =  mem::transmute(&receive_buffer);
            static mut nonce2: nonce_t = 0;

            // Output to application processor dependent on command received
            match command.opcode {
                    3 => process_boot(nonce2, *command),
                    1 => process_scan(),       
                    2 => {
                        nonce2 = generate_nonce();
                        process_validate(nonce2, *command);
                    }
                    4 => process_attest(),
                    _=> printf("Invalid opcode, recieved %d \n\0".as_bytes().as_ptr(), command.opcode as u32),
            }
    }
}

/*
fn process_boot(expected_nonce: nonce_t, command: &command_message) -> () {
    if expected_nonce == 0 {
        unsafe { printf("nonce2 is not generated\n\0".as_bytes().as_ptr()) } ;
        return ();
    }
    
    let nonce2: nonce_t = unsafe { mem::transmute(command.params[..mem::size_of::<nonce_t>()]) }

    if expected_nonce != nonce2 {
        unsafe { printf("Could not validate AP\n\0".as_bytes().as_ptr()) };
        return;
    }

/* fx
    uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
    memcpy((void*)transmit_buffer, COMPONENT_BOOT_MSG, len);

    secure_send(transmit_buffer, len);
    // Call the boot function
    */

    unsafe { boot() };
}*/
