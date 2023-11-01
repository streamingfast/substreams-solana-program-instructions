use anyhow::anyhow;
use {
    substreams::errors::Error,
    crate::{token_instruction_2022::TokenInstruction},
};

#[cfg(feature = "serde-traits")]
use {
    crate::serialization::coption_fromstr,
    serde::{Deserialize, Serialize},
};
use crate::option::COption;
use crate::pubkey::Pubkey;

/// Transfer Fee extension instructions
#[cfg_attr(feature = "serde-traits", derive(Serialize, Deserialize))]
#[cfg_attr(
    feature = "serde-traits",
    serde(rename_all = "camelCase", rename_all_fields = "camelCase")
)]
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum TransferFeeInstruction {
    /// Initialize the transfer fee on a new mint.
    ///
    /// Fails if the mint has already been initialized, so must be called before
    /// `InitializeMint`.
    ///
    /// The mint must have exactly enough space allocated for the base mint (82
    /// bytes), plus 83 bytes of padding, 1 byte reserved for the account type,
    /// then space required for this extension, plus any others.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The mint to initialize.
    InitializeTransferFeeConfig {
        /// Pubkey that may update the fees
        #[cfg_attr(feature = "serde-traits", serde(with = "coption_fromstr"))]
        transfer_fee_config_authority: COption<Pubkey>,
        /// Withdraw instructions must be signed by this key
        #[cfg_attr(feature = "serde-traits", serde(with = "coption_fromstr"))]
        withdraw_withheld_authority: COption<Pubkey>,
        /// Amount of transfer collected as fees, expressed as basis points of the
        /// transfer amount
        transfer_fee_basis_points: u16,
        /// Maximum fee assessed on transfers
        maximum_fee: u64,
    },
    /// Transfer, providing expected mint information and fees
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single owner/delegate
    ///   0. `[writable]` The source account. Must include the `TransferFeeAmount` extension.
    ///   1. `[]` The token mint. Must include the `TransferFeeConfig` extension.
    ///   2. `[writable]` The destination account. Must include the `TransferFeeAmount` extension.
    ///   3. `[signer]` The source account's owner/delegate.
    ///
    ///   * Multisignature owner/delegate
    ///   0. `[writable]` The source account.
    ///   1. `[]` The token mint.
    ///   2. `[writable]` The destination account.
    ///   3. `[]` The source account's multisignature owner/delegate.
    ///   4. ..4+M `[signer]` M signer accounts.
    TransferCheckedWithFee {
        /// The amount of tokens to transfer.
        amount: u64,
        /// Expected number of base 10 digits to the right of the decimal place.
        decimals: u8,
        /// Expected fee assessed on this transfer, calculated off-chain based on
        /// the transfer_fee_basis_points and maximum_fee of the mint.
        fee: u64,
    },
    /// Transfer all withheld tokens in the mint to an account. Signed by the mint's
    /// withdraw withheld tokens authority.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single owner/delegate
    ///   0. `[writable]` The token mint. Must include the `TransferFeeConfig` extension.
    ///   1. `[writable]` The fee receiver account. Must include the `TransferFeeAmount` extension
    ///      associated with the provided mint.
    ///   2. `[signer]` The mint's `withdraw_withheld_authority`.
    ///
    ///   * Multisignature owner/delegate
    ///   0. `[writable]` The token mint.
    ///   1. `[writable]` The destination account.
    ///   2. `[]` The mint's multisig `withdraw_withheld_authority`.
    ///   3. ..3+M `[signer]` M signer accounts.
    WithdrawWithheldTokensFromMint,
    /// Transfer all withheld tokens to an account. Signed by the mint's
    /// withdraw withheld tokens authority.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single owner/delegate
    ///   0. `[]` The token mint. Must include the `TransferFeeConfig` extension.
    ///   1. `[writable]` The fee receiver account. Must include the `TransferFeeAmount`
    ///      extension and be associated with the provided mint.
    ///   2. `[signer]` The mint's `withdraw_withheld_authority`.
    ///   3. ..3+N `[writable]` The source accounts to withdraw from.
    ///
    ///   * Multisignature owner/delegate
    ///   0. `[]` The token mint.
    ///   1. `[writable]` The destination account.
    ///   2. `[]` The mint's multisig `withdraw_withheld_authority`.
    ///   3. ..3+M `[signer]` M signer accounts.
    ///   3+M+1. ..3+M+N `[writable]` The source accounts to withdraw from.
    WithdrawWithheldTokensFromAccounts {
        /// Number of token accounts harvested
        num_token_accounts: u8,
    },
    /// Permissionless instruction to transfer all withheld tokens to the mint.
    ///
    /// Succeeds for frozen accounts.
    ///
    /// Accounts provided should include the `TransferFeeAmount` extension. If not,
    /// the account is skipped.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The mint.
    ///   1. ..1+N `[writable]` The source accounts to harvest from.
    HarvestWithheldTokensToMint,
    /// Set transfer fee. Only supported for mints that include the `TransferFeeConfig` extension.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single authority
    ///   0. `[writable]` The mint.
    ///   1. `[signer]` The mint's fee account owner.
    ///
    ///   * Multisignature authority
    ///   0. `[writable]` The mint.
    ///   1. `[]` The mint's multisignature fee account owner.
    ///   2. ..2+M `[signer]` M signer accounts.
    SetTransferFee {
        /// Amount of transfer collected as fees, expressed as basis points of the
        /// transfer amount
        transfer_fee_basis_points: u16,
        /// Maximum fee assessed on transfers
        maximum_fee: u64,
    },
}
impl TransferFeeInstruction {
    /// Unpacks a byte buffer into a TransferFeeInstruction
    pub fn unpack(input: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (&tag, rest) = input.split_first().ok_or(anyhow!("Invalid Transfer Fee Instruction"))?;
        Ok(match tag {
            0 => {
                let (transfer_fee_config_authority, rest) =
                    TokenInstruction::unpack_pubkey_option(rest)?;
                let (withdraw_withheld_authority, rest) =
                    TokenInstruction::unpack_pubkey_option(rest)?;
                let (transfer_fee_basis_points, rest) = TokenInstruction::unpack_u16(rest)?;
                let (maximum_fee, rest) = TokenInstruction::unpack_u64(rest)?;
                let instruction = Self::InitializeTransferFeeConfig {
                    transfer_fee_config_authority,
                    withdraw_withheld_authority,
                    transfer_fee_basis_points,
                    maximum_fee,
                };
                (instruction, rest)
            }
            1 => {
                let (amount, decimals, rest) = TokenInstruction::unpack_amount_decimals(rest)?;
                let (fee, rest) = TokenInstruction::unpack_u64(rest)?;
                let instruction = Self::TransferCheckedWithFee {
                    amount,
                    decimals,
                    fee,
                };
                (instruction, rest)
            }
            2 => (Self::WithdrawWithheldTokensFromMint, rest),
            3 => {
                let (&num_token_accounts, rest) = rest.split_first().ok_or(anyhow!("Invalid Transfer Fee Instruction - 3"))?;
                let instruction = Self::WithdrawWithheldTokensFromAccounts { num_token_accounts };
                (instruction, rest)
            }
            4 => (Self::HarvestWithheldTokensToMint, rest),
            5 => {
                let (transfer_fee_basis_points, rest) = TokenInstruction::unpack_u16(rest)?;
                let (maximum_fee, rest) = TokenInstruction::unpack_u64(rest)?;
                let instruction = Self::SetTransferFee {
                    transfer_fee_basis_points,
                    maximum_fee,
                };
                (instruction, rest)
            }
            _ => return Err(anyhow!("Invalid Transfer Fee Instruction - unpack didn't match any tag value: {}", tag)),
        })
    }
}