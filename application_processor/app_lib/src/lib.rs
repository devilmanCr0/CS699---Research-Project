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
use hex_display::HexDisplayExt;

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
        unsafe { LED_Off(0) }; // LED_RED
        loop {}
}

enum PrintType {
        Info    = 0,
        Success = 1,
        Error   = 2,
}

extern {
        fn secure_send(address: u8, buffer: *mut u8, len: u8) -> i32;
        fn secure_receive(address: u8, buffer: *mut u8) -> i32;
        fn generate_nonce() -> nonce_t; 
        fn component_id_to_i2c_addr(component_id: u32) -> i2c_addr_t;
        fn boot() -> ();
        fn print_stuff(print_type: i32, format: *const u8, ...) -> ();
        fn recv_input(msg: *const u8, buf: *mut u8, buf_len: i32) -> ();
        fn attest_component(component_id: u32) -> i32;
        fn hash(data: *mut u8, len: usize, hash_out: *mut u8) -> i32;
        
        fn LED_Off(idx: u32) -> (); // A MAX78000 msdk-specific function

        static flash_status: flash_entry;
        static PIN_HEAD: *const u8;
        static TOKEN_HEAD: *const u8;
}

#[no_mangle]
pub extern "C" fn attempt_boot() -> () {
        let nonce_verification: &mut [nonce_t; 2] = &mut [ 0x1122334455667788 as nonce_t ; 2 ];
        if validate_components(nonce_verification) == 1 {
                unsafe{ print_stuff(PrintType::Error as i32, "Components could not be validated\n\0".as_bytes().as_ptr()) };
                return ();
        }

        unsafe{ print_stuff(PrintType::Info as i32, "Components validated\n\0".as_bytes().as_ptr()) };

        if boot_components(nonce_verification) == 1 {
                unsafe{ print_stuff(PrintType::Error as i32, "Failed to boot all components\n\0".as_bytes().as_ptr()) };
                return ();
        }

        unsafe{ boot() };
}


#[no_mangle]
pub extern "C" fn scan_components() -> i32 {
        let mut count: u32 = unsafe { flash_status.component_cnt };
        let count_index: usize = unsafe { flash_status.component_cnt as usize };
        
        let mut receive_buffer: [u8; MAX_I2C_MESSAGE_LEN] = [0; MAX_I2C_MESSAGE_LEN];
        
        let mut command = command_message {
                opcode: component_cmd_t::COMPONENT_CMD_SCAN as u8,
                params: [0; MAX_I2C_MESSAGE_LEN-1],
        };

        for i in 0..count_index {
                unsafe { print_stuff(PrintType::Info as i32, "P>0x%08x\n\0".as_bytes().as_ptr(), flash_status.component_ids[i]) };
                let addr: i2c_addr_t = unsafe { component_id_to_i2c_addr(flash_status.component_ids[i]) };
               
                if addr == 0x18 || addr == 0x28 || addr == 0x36 {
                   continue;
                }

                // Generate nonce1 for validating component
                let nonce1: nonce_t = unsafe { generate_nonce() };
               
                let command_param: &mut [u8] = &mut command.params[..];
                command_param[..mem::size_of::<nonce_t>() as usize].copy_from_slice(&nonce1.to_be_bytes());// Request the component to send this nonce1 back

                // debugging for sanity check sake  
                // unsafe { print_stuff(PrintType::Info as i32, "our amazing value is %u \n\0".as_bytes().as_ptr(), &command.params[..mem::size_of::<nonce_t>() as usize]) }; 

                // Send out command and receive result
                match issue_cmd(addr, &mut command, &mut receive_buffer) {
                        Ok(_len) => {

                                let validate: &validate_message = unsafe { mem::transmute(&receive_buffer)  };
                               // &receive_buffer[..mem::size_of::<validate_message>()])

                                // Remake validate_message structure
                                if validate.nonce1 != nonce1 {
                                    unsafe { print_stuff(PrintType::Info as i32, "nonce1 value invalid, was %u, is now %u\n\0"
                                             .as_bytes().as_ptr(), nonce1, validate.nonce1) };
                                    continue;
                                }
                                  
                                // Success, device is present
                                unsafe { print_stuff(PrintType::Info as i32, "F>0x%08x\n\0".as_bytes().as_ptr(), validate.component_id) };

                                if validate.component_id == unsafe { flash_status.component_ids[i] } {
                                        count-=1; 
                                }
                        }
                        Err(_) => unsafe { print_stuff(PrintType::Error as i32, "unable to read, issue_cmd failed\n\0".as_bytes().as_ptr()) } 
                }
        }

            if count != 0 {
               unsafe { print_stuff(PrintType::Error as i32, "List failed\n\0".as_bytes().as_ptr()) };
               return return_codes::ERROR_RETURN as i32;
            }

            unsafe { print_stuff(PrintType::Success as i32, "List\n\0".as_bytes().as_ptr()) };
            return return_codes::SUCCESS_RETURN as i32;
                
}


fn validate_components(nonce_array: &mut [nonce_t]) -> i32 {
        let count_index: usize = unsafe { flash_status.component_cnt as usize };
        
        let mut receive_buffer: [u8; MAX_I2C_MESSAGE_LEN] = [0; MAX_I2C_MESSAGE_LEN];
        
        let mut command = command_message {
                opcode: component_cmd_t::COMPONENT_CMD_VALIDATE as u8,
                params: [0; MAX_I2C_MESSAGE_LEN-1],
        };

        for i in 0..count_index {
                let addr: i2c_addr_t = unsafe { component_id_to_i2c_addr(flash_status.component_ids[i]) };

                // Generate nonce1 for validating component
                let nonce1: nonce_t = unsafe { generate_nonce() };

                let command_param: &mut [u8] = &mut command.params[..];
                command_param[..mem::size_of::<nonce_t>() as usize].copy_from_slice(&nonce1.to_be_bytes());// Request the component to send this nonce1 back

                match issue_cmd(addr, &mut command, &mut receive_buffer) {
                        Ok(_len) => {

                                let validate: &validate_message = unsafe { mem::transmute(&receive_buffer)  };
                               // &receive_buffer[..mem::size_of::<validate_message>()])

                                // Remake validate_message structure
                                if validate.nonce1 != nonce1 {
                                    unsafe { print_stuff(PrintType::Error as i32, "nonce1 value invalid\n\0".as_bytes().as_ptr()) };
                                    return return_codes::ERROR_RETURN as i32;
                                }
                                  

                                if validate.component_id != unsafe { flash_status.component_ids[i] } {
                                    unsafe { print_stuff(PrintType::Error as i32, "Component ID 0x%08x invalid \n\0".as_bytes().as_ptr(), flash_status.component_ids[i]) };
                                    return return_codes::ERROR_RETURN as i32;
                                }
                                
                                nonce_array[i] = validate.nonce2;
                        }
                        Err(_) => unsafe { print_stuff(PrintType::Error as i32, "could not validate component\n\0".as_bytes().as_ptr()) } 
                }

        }
    return return_codes::SUCCESS_RETURN as i32;
}

fn boot_components(nonce_verification: &[nonce_t]) -> i32 {
                let count_index: usize = unsafe { flash_status.component_cnt as usize };
                
                let mut receive_buffer: [u8; MAX_I2C_MESSAGE_LEN] = [0; MAX_I2C_MESSAGE_LEN];
               
                // Send command to boot components so we could provide our part of the verification
                let mut command = command_message {
                        opcode: component_cmd_t::COMPONENT_CMD_BOOT as u8,
                        params: [0; MAX_I2C_MESSAGE_LEN-1],
                };

                for i in 0..count_index {
                        let addr: i2c_addr_t = unsafe { component_id_to_i2c_addr(flash_status.component_ids[i]) };

                        // To allow the components to verify our end of integrity
                        let command_param: &mut [u8] = &mut command.params[..];
                        command_param[..mem::size_of::<nonce_t>() as usize].copy_from_slice(&nonce_verification[i].to_be_bytes());

                        match issue_cmd(addr, &mut command, &mut receive_buffer) {
                                Ok(_len) => {
                                        unsafe { print_stuff(PrintType::Info as i32, "0x%08x%s\n\0".as_bytes().as_ptr(), flash_status.component_ids[i], receive_buffer) };
                                }                                      
                                Err(_) => unsafe { print_stuff(PrintType::Error as i32, "Could not boot components\n\0".as_bytes().as_ptr()) } 
                        }

                }

            return return_codes::SUCCESS_RETURN as i32;
}

/*
#[no_mangle]
pub extern "C" fn attempt_replace() -> () {

}
*/

#[no_mangle]
pub extern "C" fn attempt_attest() -> () {
    const BUFFER_SIZE: usize = 50;
    let mut buffer: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];

    if validate_pin() == return_codes::SUCCESS_RETURN {
        return ();
    }

    unsafe { recv_input("Component ID: ".as_bytes().as_ptr(), buffer.as_mut_ptr(), BUFFER_SIZE as i32) };
    let mut sliced: [u8; 4] = [0; 4];
    sliced.copy_from_slice(&buffer[..4]);
    let component_id: u32 = u32::from_be_bytes(sliced);

    if unsafe { attest_component(component_id) }  == return_codes::SUCCESS_RETURN as i32 {
        unsafe { print_stuff(PrintType::Success as i32, "Attest\n\0".as_bytes().as_ptr()) };
    }
}


fn validate_pin() -> return_codes {
    let mut buffer: [u8; PIN_LENGTH] = [0; PIN_LENGTH]; // Should be generated by deployment
    let mut hash_out: [u8; HASH_LENGTH] = [0; HASH_LENGTH];


    let passcode_pin: &[u8; PIN_LENGTH] = unsafe { mem::transmute(PIN_HEAD) };
    unsafe { print_stuff(PrintType::Info as i32, "Passed the transmute\n\0".as_bytes().as_ptr()) };

    unsafe { recv_input("Enter pin: \0".as_bytes().as_ptr() , buffer.as_mut_ptr(), PIN_LENGTH as i32) };

    if unsafe { hash(buffer.as_mut_ptr(), PIN_LENGTH, hash_out.as_mut_ptr()) } != 0 {
        unsafe { print_stuff(PrintType::Error as i32, "Error: hash\n\0".as_bytes().as_ptr()) };
        return return_codes::ERROR_RETURN;
    }
    
    // The hash string is encoded in bytes that we need to unfold
    // and print out to compare the passcode properly
    let mut hash_to_string: [u8; PIN_LENGTH] = [0; PIN_LENGTH];
    hash_to_string.copy_from_slice(&hash_out.hex().0[..]);
    
    // Compares the hashes!
    if  hash_to_string == *passcode_pin {
        unsafe { print_stuff(PrintType::Info as i32, "Pin Accepted!\n\0".as_bytes().as_ptr()) };
        return return_codes::SUCCESS_RETURN;
    }

    unsafe { print_stuff(PrintType::Error as i32, "Invalid PIN!\n\0".as_bytes().as_ptr()) };
    return return_codes::ERROR_RETURN;
}



#[no_mangle]
pub extern "C" fn validate_token() -> i32 {
    let mut buffer: [u8; TOKEN_LENGTH] = [0; TOKEN_LENGTH]; // Should be generated by deployment
    let mut hash_out: [u8; HASH_LENGTH] = [0; HASH_LENGTH];

    let passcode_token: &[u8; TOKEN_LENGTH] = unsafe { mem::transmute(TOKEN_HEAD) };

    unsafe { recv_input("Enter token pin: \n\0".as_bytes().as_ptr() , buffer.as_mut_ptr(), TOKEN_LENGTH as i32) };

    if unsafe { hash(buffer.as_mut_ptr(), TOKEN_LENGTH, hash_out.as_mut_ptr()) } != 0 {
        unsafe { print_stuff(PrintType::Error as i32, "Error: hash\n\0".as_bytes().as_ptr()) };
        return return_codes::ERROR_RETURN as i32;
    }
   
    // The hash string is encoded in bytes that we need to unfold
    // and print out to compare the passcode properly
    let mut hash_to_string: [u8; TOKEN_LENGTH] = [0; TOKEN_LENGTH];
    hash_to_string.copy_from_slice(&hash_out.hex().0[..TOKEN_LENGTH]); // After hash, grab hex value

    // Compares the hashes!
    if  hash_to_string == *passcode_token {
        unsafe { print_stuff(PrintType::Info as i32, "Token Accepted!\n\0".as_bytes().as_ptr()) };
        return return_codes::SUCCESS_RETURN as i32;
    }

    unsafe { print_stuff(PrintType::Error as i32, "Invalid Token!\n\0".as_bytes().as_ptr()) };

    return return_codes::ERROR_RETURN as i32;

}




fn issue_cmd(addr: i2c_addr_t, transmit: &mut command_message, receive: &mut [u8]) -> Result<i32, ()> { 
    let transmit_buffer: &mut [u8; MAX_I2C_MESSAGE_LEN] = unsafe { mem::transmute(transmit) };

    let result: i32 = unsafe { secure_send(addr, transmit_buffer.as_mut_ptr(), mem::size_of::<nonce_t>() as u8 + 1) }; 
    // sizeof(nonce) + sizeof(opcode)
    
    if result == return_codes::ERROR_RETURN as i32 {
        return Err(());
    }
    
    // receiving message and checking its result...
    let len: i32 = unsafe { secure_receive(addr, receive.as_mut_ptr()) };
    if len == return_codes::ERROR_RETURN as i32 {
        return Err(());
    }

    // Debugging to check if data is being received and sent properly
    // let test: &validate_message = unsafe { mem::transmute(&receive) };
    // unsafe { print_stuff(PrintType::Info as i32, "our amazing value is %x \n\0".as_bytes().as_ptr(), &test.component_id) }; 
    
    return Ok(len); 
}






