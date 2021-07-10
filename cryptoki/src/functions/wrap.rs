// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Signing and authentication functions

use crate::get_pkcs11;
use crate::types::function::Rv;
use crate::types::mechanism::Mechanism;
use crate::types::object::ObjectHandle;
use crate::types::session::Session;
use crate::Result;
use cryptoki_sys::*;
use std::convert::TryInto;

impl<'a> Session<'a> {
    /// Wrap key with mechanism
    pub fn wrap(
        &self,
        mechanism: &Mechanism,
        wrapping_key: ObjectHandle,
        key_to_wrap: ObjectHandle,
    ) -> Result<Vec<u8>> {
        let mut mechanism: CK_MECHANISM = mechanism.into();
        let mut wrapped_key_len = 0;

        // Get the wrapped key length
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_WrapKey)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                wrapping_key.handle(),
                key_to_wrap.handle(),
                std::ptr::null_mut(),
                &mut wrapped_key_len,
            ))
            .into_result()?;
        }

        let mut wrapped_key = vec![0; wrapped_key_len.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_WrapKey)(
                self.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                wrapping_key.handle(),
                key_to_wrap.handle(),
                wrapped_key.as_mut_ptr(),
                &mut wrapped_key_len,
            ))
            .into_result()?;
        }

        wrapped_key.resize(wrapped_key_len.try_into()?, 0);

        Ok(wrapped_key)
    }
}
