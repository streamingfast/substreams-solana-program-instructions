//! Instruction types

#![allow(deprecated)] // needed to avoid deprecation warning when generating serde implementation for TokenInstruction

use anyhow::anyhow;
use {
    substreams::{errors::Error},
    num_enum::{IntoPrimitive, TryFromPrimitive},
    crate::{transfer_fee_instruction::TransferFeeInstruction},
    std::{
        convert::{TryFrom, TryInto},
        mem::size_of,
    },
};

#[cfg(feature = "serde-traits")]
use {
    crate::serialization::coption_fromstr,
    serde::{Deserialize, Serialize},
    serde_with::{As, DisplayFromStr},
};
use crate::option::COption;
use crate::pubkey::{Pubkey, PUBKEY_BYTES};

/// Minimum number of multisignature signers (min N)
pub const MIN_SIGNERS: usize = 1;
/// Maximum number of multisignature signers (max N)
pub const MAX_SIGNERS: usize = 11;
/// Serialized length of a u16, for unpacking
const U16_BYTES: usize = 2;
/// Serialized length of a u64, for unpacking
const U64_BYTES: usize = 8;

/// Instructions supported by the token program.
#[repr(C)]
#[cfg_attr(feature = "serde-traits", derive(Serialize, Deserialize))]
#[cfg_attr(
    feature = "serde-traits",
    serde(rename_all_fields = "camelCase", rename_all = "camelCase")
)]
#[derive(Clone, Debug, PartialEq)]
pub enum TokenInstruction<'a> {
    /// Initializes a new mint and optionally deposits all the newly minted
    /// tokens in an account.
    ///
    /// The `InitializeMint` instruction requires no signers and MUST be
    /// included within the same Transaction as the system program's
    /// `CreateAccount` instruction that creates the account being initialized.
    /// Otherwise another party can acquire ownership of the uninitialized
    /// account.
    ///
    /// All extensions must be initialized before calling this instruction.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The mint to initialize.
    ///   1. `[]` Rent sysvar
    ///
    InitializeMint {
        /// Number of base 10 digits to the right of the decimal place.
        decimals: u8,
        /// The authority/multisignature to mint tokens.
        #[cfg_attr(feature = "serde-traits", serde(with = "As::<DisplayFromStr>"))]
        mint_authority: Pubkey,
        /// The freeze authority/multisignature of the mint.
        #[cfg_attr(feature = "serde-traits", serde(with = "coption_fromstr"))]
        freeze_authority: COption<Pubkey>,
    },
    /// Initializes a new account to hold tokens.  If this account is associated
    /// with the native mint then the token balance of the initialized account
    /// will be equal to the amount of SOL in the account. If this account is
    /// associated with another mint, that mint must be initialized before this
    /// command can succeed.
    ///
    /// The `InitializeAccount` instruction requires no signers and MUST be
    /// included within the same Transaction as the system program's
    /// `CreateAccount` instruction that creates the account being initialized.
    /// Otherwise another party can acquire ownership of the uninitialized
    /// account.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]`  The account to initialize.
    ///   1. `[]` The mint this account will be associated with.
    ///   2. `[]` The new account's owner/multisignature.
    ///   3. `[]` Rent sysvar
    InitializeAccount,
    /// Initializes a multisignature account with N provided signers.
    ///
    /// Multisignature accounts can used in place of any single owner/delegate
    /// accounts in any token instruction that require an owner/delegate to be
    /// present.  The variant field represents the number of signers (M)
    /// required to validate this multisignature account.
    ///
    /// The `InitializeMultisig` instruction requires no signers and MUST be
    /// included within the same Transaction as the system program's
    /// `CreateAccount` instruction that creates the account being initialized.
    /// Otherwise another party can acquire ownership of the uninitialized
    /// account.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The multisignature account to initialize.
    ///   1. `[]` Rent sysvar
    ///   2. ..2+N. `[]` The signer accounts, must equal to N where 1 <= N <=
    ///      11.
    InitializeMultisig {
        /// The number of signers (M) required to validate this multisignature
        /// account.
        m: u8,
    },
    /// NOTE This instruction is deprecated in favor of `TransferChecked` or
    /// `TransferCheckedWithFee`
    ///
    /// Transfers tokens from one account to another either directly or via a
    /// delegate.  If this account is associated with the native mint then equal
    /// amounts of SOL and Tokens will be transferred to the destination
    /// account.
    ///
    /// If either account contains an `TransferFeeAmount` extension, this will fail.
    /// Mints with the `TransferFeeConfig` extension are required in order to assess the fee.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single owner/delegate
    ///   0. `[writable]` The source account.
    ///   1. `[writable]` The destination account.
    ///   2. `[signer]` The source account's owner/delegate.
    ///
    ///   * Multisignature owner/delegate
    ///   0. `[writable]` The source account.
    ///   1. `[writable]` The destination account.
    ///   2. `[]` The source account's multisignature owner/delegate.
    ///   3. ..3+M `[signer]` M signer accounts.
    #[deprecated(
        since = "4.0.0",
        note = "please use `TransferChecked` or `TransferCheckedWithFee` instead"
    )]
    Transfer {
        /// The amount of tokens to transfer.
        amount: u64,
    },
    /// Approves a delegate.  A delegate is given the authority over tokens on
    /// behalf of the source account's owner.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single owner
    ///   0. `[writable]` The source account.
    ///   1. `[]` The delegate.
    ///   2. `[signer]` The source account owner.
    ///
    ///   * Multisignature owner
    ///   0. `[writable]` The source account.
    ///   1. `[]` The delegate.
    ///   2. `[]` The source account's multisignature owner.
    ///   3. ..3+M `[signer]` M signer accounts
    Approve {
        /// The amount of tokens the delegate is approved for.
        amount: u64,
    },
    /// Revokes the delegate's authority.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single owner
    ///   0. `[writable]` The source account.
    ///   1. `[signer]` The source account owner or current delegate.
    ///
    ///   * Multisignature owner
    ///   0. `[writable]` The source account.
    ///   1. `[]` The source account's multisignature owner or current delegate.
    ///   2. ..2+M `[signer]` M signer accounts
    Revoke,
    /// Sets a new authority of a mint or account.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single authority
    ///   0. `[writable]` The mint or account to change the authority of.
    ///   1. `[signer]` The current authority of the mint or account.
    ///
    ///   * Multisignature authority
    ///   0. `[writable]` The mint or account to change the authority of.
    ///   1. `[]` The mint's or account's current multisignature authority.
    ///   2. ..2+M `[signer]` M signer accounts
    SetAuthority {
        /// The type of authority to update.
        authority_type: AuthorityType,
        /// The new authority
        #[cfg_attr(feature = "serde-traits", serde(with = "coption_fromstr"))]
        new_authority: COption<Pubkey>,
    },
    /// Mints new tokens to an account.  The native mint does not support
    /// minting.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single authority
    ///   0. `[writable]` The mint.
    ///   1. `[writable]` The account to mint tokens to.
    ///   2. `[signer]` The mint's minting authority.
    ///
    ///   * Multisignature authority
    ///   0. `[writable]` The mint.
    ///   1. `[writable]` The account to mint tokens to.
    ///   2. `[]` The mint's multisignature mint-tokens authority.
    ///   3. ..3+M `[signer]` M signer accounts.
    MintTo {
        /// The amount of new tokens to mint.
        amount: u64,
    },
    /// Burns tokens by removing them from an account.  `Burn` does not support
    /// accounts associated with the native mint, use `CloseAccount` instead.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single owner/delegate
    ///   0. `[writable]` The account to burn from.
    ///   1. `[writable]` The token mint.
    ///   2. `[signer]` The account's owner/delegate.
    ///
    ///   * Multisignature owner/delegate
    ///   0. `[writable]` The account to burn from.
    ///   1. `[writable]` The token mint.
    ///   2. `[]` The account's multisignature owner/delegate.
    ///   3. ..3+M `[signer]` M signer accounts.
    Burn {
        /// The amount of tokens to burn.
        amount: u64,
    },
    /// Close an account by transferring all its SOL to the destination account.
    /// Non-native accounts may only be closed if its token amount is zero.
    ///
    /// Accounts with the `TransferFeeAmount` extension may only be closed if the withheld
    /// amount is zero.
    ///
    /// Accounts with the `ConfidentialTransfer` extension may only be closed if the pending and
    /// available balance ciphertexts are empty. Use
    /// `ConfidentialTransferInstruction::ApplyPendingBalance` and
    /// `ConfidentialTransferInstruction::EmptyAccount` to empty these ciphertexts.
    ///
    /// Accounts with the `ConfidentialTransferFee` extension may only be closed if the withheld
    /// amount ciphertext is empty. Use
    /// `ConfidentialTransferFeeInstruction::HarvestWithheldTokensToMint` to empty this ciphertext.
    ///
    /// Mints may be closed if they have the `MintCloseAuthority` extension and their token
    /// supply is zero
    ///
    /// Accounts
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single owner
    ///   0. `[writable]` The account to close.
    ///   1. `[writable]` The destination account.
    ///   2. `[signer]` The account's owner.
    ///
    ///   * Multisignature owner
    ///   0. `[writable]` The account to close.
    ///   1. `[writable]` The destination account.
    ///   2. `[]` The account's multisignature owner.
    ///   3. ..3+M `[signer]` M signer accounts.
    CloseAccount,
    /// Freeze an Initialized account using the Mint's freeze_authority (if
    /// set).
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single owner
    ///   0. `[writable]` The account to freeze.
    ///   1. `[]` The token mint.
    ///   2. `[signer]` The mint freeze authority.
    ///
    ///   * Multisignature owner
    ///   0. `[writable]` The account to freeze.
    ///   1. `[]` The token mint.
    ///   2. `[]` The mint's multisignature freeze authority.
    ///   3. ..3+M `[signer]` M signer accounts.
    FreezeAccount,
    /// Thaw a Frozen account using the Mint's freeze_authority (if set).
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single owner
    ///   0. `[writable]` The account to freeze.
    ///   1. `[]` The token mint.
    ///   2. `[signer]` The mint freeze authority.
    ///
    ///   * Multisignature owner
    ///   0. `[writable]` The account to freeze.
    ///   1. `[]` The token mint.
    ///   2. `[]` The mint's multisignature freeze authority.
    ///   3. ..3+M `[signer]` M signer accounts.
    ThawAccount,

    /// Transfers tokens from one account to another either directly or via a
    /// delegate.  If this account is associated with the native mint then equal
    /// amounts of SOL and Tokens will be transferred to the destination
    /// account.
    ///
    /// This instruction differs from Transfer in that the token mint and
    /// decimals value is checked by the caller.  This may be useful when
    /// creating transactions offline or within a hardware wallet.
    ///
    /// If either account contains an `TransferFeeAmount` extension, the fee is
    /// withheld in the destination account.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single owner/delegate
    ///   0. `[writable]` The source account.
    ///   1. `[]` The token mint.
    ///   2. `[writable]` The destination account.
    ///   3. `[signer]` The source account's owner/delegate.
    ///
    ///   * Multisignature owner/delegate
    ///   0. `[writable]` The source account.
    ///   1. `[]` The token mint.
    ///   2. `[writable]` The destination account.
    ///   3. `[]` The source account's multisignature owner/delegate.
    ///   4. ..4+M `[signer]` M signer accounts.
    TransferChecked {
        /// The amount of tokens to transfer.
        amount: u64,
        /// Expected number of base 10 digits to the right of the decimal place.
        decimals: u8,
    },
    /// Approves a delegate.  A delegate is given the authority over tokens on
    /// behalf of the source account's owner.
    ///
    /// This instruction differs from Approve in that the token mint and
    /// decimals value is checked by the caller.  This may be useful when
    /// creating transactions offline or within a hardware wallet.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single owner
    ///   0. `[writable]` The source account.
    ///   1. `[]` The token mint.
    ///   2. `[]` The delegate.
    ///   3. `[signer]` The source account owner.
    ///
    ///   * Multisignature owner
    ///   0. `[writable]` The source account.
    ///   1. `[]` The token mint.
    ///   2. `[]` The delegate.
    ///   3. `[]` The source account's multisignature owner.
    ///   4. ..4+M `[signer]` M signer accounts
    ApproveChecked {
        /// The amount of tokens the delegate is approved for.
        amount: u64,
        /// Expected number of base 10 digits to the right of the decimal place.
        decimals: u8,
    },
    /// Mints new tokens to an account.  The native mint does not support
    /// minting.
    ///
    /// This instruction differs from MintTo in that the decimals value is
    /// checked by the caller.  This may be useful when creating transactions
    /// offline or within a hardware wallet.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single authority
    ///   0. `[writable]` The mint.
    ///   1. `[writable]` The account to mint tokens to.
    ///   2. `[signer]` The mint's minting authority.
    ///
    ///   * Multisignature authority
    ///   0. `[writable]` The mint.
    ///   1. `[writable]` The account to mint tokens to.
    ///   2. `[]` The mint's multisignature mint-tokens authority.
    ///   3. ..3+M `[signer]` M signer accounts.
    MintToChecked {
        /// The amount of new tokens to mint.
        amount: u64,
        /// Expected number of base 10 digits to the right of the decimal place.
        decimals: u8,
    },
    /// Burns tokens by removing them from an account.  `BurnChecked` does not
    /// support accounts associated with the native mint, use `CloseAccount`
    /// instead.
    ///
    /// This instruction differs from Burn in that the decimals value is checked
    /// by the caller. This may be useful when creating transactions offline or
    /// within a hardware wallet.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single owner/delegate
    ///   0. `[writable]` The account to burn from.
    ///   1. `[writable]` The token mint.
    ///   2. `[signer]` The account's owner/delegate.
    ///
    ///   * Multisignature owner/delegate
    ///   0. `[writable]` The account to burn from.
    ///   1. `[writable]` The token mint.
    ///   2. `[]` The account's multisignature owner/delegate.
    ///   3. ..3+M `[signer]` M signer accounts.
    BurnChecked {
        /// The amount of tokens to burn.
        amount: u64,
        /// Expected number of base 10 digits to the right of the decimal place.
        decimals: u8,
    },
    /// Like InitializeAccount, but the owner pubkey is passed via instruction data
    /// rather than the accounts list. This variant may be preferable when using
    /// Cross Program Invocation from an instruction that does not need the owner's
    /// `AccountInfo` otherwise.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]`  The account to initialize.
    ///   1. `[]` The mint this account will be associated with.
    ///   2. `[]` Rent sysvar
    InitializeAccount2 {
        /// The new account's owner/multisignature.
        #[cfg_attr(feature = "serde-traits", serde(with = "As::<DisplayFromStr>"))]
        owner: Pubkey,
    },
    /// Given a wrapped / native token account (a token account containing SOL)
    /// updates its amount field based on the account's underlying `lamports`.
    /// This is useful if a non-wrapped SOL account uses `system_instruction::transfer`
    /// to move lamports to a wrapped token account, and needs to have its token
    /// `amount` field updated.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]`  The native token account to sync with its underlying lamports.
    SyncNative,
    /// Like InitializeAccount2, but does not require the Rent sysvar to be provided
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]`  The account to initialize.
    ///   1. `[]` The mint this account will be associated with.
    InitializeAccount3 {
        /// The new account's owner/multisignature.
        #[cfg_attr(feature = "serde-traits", serde(with = "As::<DisplayFromStr>"))]
        owner: Pubkey,
    },
    /// Like InitializeMultisig, but does not require the Rent sysvar to be provided
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The multisignature account to initialize.
    ///   1. ..1+N. `[]` The signer accounts, must equal to N where 1 <= N <=
    ///      11.
    InitializeMultisig2 {
        /// The number of signers (M) required to validate this multisignature
        /// account.
        m: u8,
    },
    /// Like InitializeMint, but does not require the Rent sysvar to be provided
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The mint to initialize.
    ///
    InitializeMint2 {
        /// Number of base 10 digits to the right of the decimal place.
        decimals: u8,
        /// The authority/multisignature to mint tokens.
        #[cfg_attr(feature = "serde-traits", serde(with = "As::<DisplayFromStr>"))]
        mint_authority: Pubkey,
        /// The freeze authority/multisignature of the mint.
        #[cfg_attr(feature = "serde-traits", serde(with = "coption_fromstr"))]
        freeze_authority: COption<Pubkey>,
    },
    /// Gets the required size of an account for the given mint as a little-endian
    /// `u64`.
    ///
    /// Return data can be fetched using `sol_get_return_data` and deserializing
    /// the return data as a little-endian `u64`.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[]` The mint to calculate for
    GetAccountDataSize {
        /// Additional extension types to include in the returned account size
        extension_types: Vec<ExtensionType>,
    },
    /// Initialize the Immutable Owner extension for the given token account
    ///
    /// Fails if the account has already been initialized, so must be called before
    /// `InitializeAccount`.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]`  The account to initialize.
    ///
    /// Data expected by this instruction:
    ///   None
    ///
    InitializeImmutableOwner,
    /// Convert an Amount of tokens to a UiAmount `string`, using the given mint.
    ///
    /// Fails on an invalid mint.
    ///
    /// Return data can be fetched using `sol_get_return_data` and deserialized with
    /// `String::from_utf8`.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[]` The mint to calculate for
    AmountToUiAmount {
        /// The amount of tokens to convert.
        amount: u64,
    },
    /// Convert a UiAmount of tokens to a little-endian `u64` raw Amount, using the given mint.
    ///
    /// Return data can be fetched using `sol_get_return_data` and deserializing
    /// the return data as a little-endian `u64`.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[]` The mint to calculate for
    UiAmountToAmount {
        /// The ui_amount of tokens to convert.
        ui_amount: &'a str,
    },
    /// Initialize the close account authority on a new mint.
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
    InitializeMintCloseAuthority {
        /// Authority that must sign the `CloseAccount` instruction on a mint
        #[cfg_attr(feature = "serde-traits", serde(with = "coption_fromstr"))]
        close_authority: COption<Pubkey>,
    },
    /// The common instruction prefix for Transfer Fee extension instructions.
    ///
    /// See `extension::transfer_fee::instruction::TransferFeeInstruction` for
    /// further details about the extended instructions that share this instruction prefix
    TransferFeeExtension(TransferFeeInstruction),
    /// The common instruction prefix for Confidential Transfer extension instructions.
    ///
    /// See `extension::confidential_transfer::instruction::ConfidentialTransferInstruction` for
    /// further details about the extended instructions that share this instruction prefix
    ConfidentialTransferExtension,
    /// The common instruction prefix for Default Account State extension instructions.
    ///
    /// See `extension::default_account_state::instruction::DefaultAccountStateInstruction` for
    /// further details about the extended instructions that share this instruction prefix
    DefaultAccountStateExtension,
    /// Check to see if a token account is large enough for a list of ExtensionTypes, and if not,
    /// use reallocation to increase the data size.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single owner
    ///   0. `[writable]` The account to reallocate.
    ///   1. `[signer, writable]` The payer account to fund reallocation
    ///   2. `[]` System program for reallocation funding
    ///   3. `[signer]` The account's owner.
    ///
    ///   * Multisignature owner
    ///   0. `[writable]` The account to reallocate.
    ///   1. `[signer, writable]` The payer account to fund reallocation
    ///   2. `[]` System program for reallocation funding
    ///   3. `[]` The account's multisignature owner/delegate.
    ///   4. ..4+M `[signer]` M signer accounts.
    ///
    Reallocate {
        /// New extension types to include in the reallocated account
        extension_types: Vec<ExtensionType>,
    },
    /// The common instruction prefix for Memo Transfer account extension instructions.
    ///
    /// See `extension::memo_transfer::instruction::RequiredMemoTransfersInstruction` for
    /// further details about the extended instructions that share this instruction prefix
    MemoTransferExtension,
    /// Creates the native mint.
    ///
    /// This instruction only needs to be invoked once after deployment and is permissionless,
    /// Wrapped SOL (`native_mint::id()`) will not be available until this instruction is
    /// successfully executed.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writeable,signer]` Funding account (must be a system account)
    ///   1. `[writable]` The native mint address
    ///   2. `[]` System program for mint account funding
    ///
    CreateNativeMint,
    /// Initialize the non transferable extension for the given mint account
    ///
    /// Fails if the account has already been initialized, so must be called before
    /// `InitializeMint`.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]`  The mint account to initialize.
    ///
    /// Data expected by this instruction:
    ///   None
    ///
    InitializeNonTransferableMint,
    /// The common instruction prefix for Interest Bearing extension instructions.
    ///
    /// See `extension::interest_bearing_mint::instruction::InterestBearingMintInstruction` for
    /// further details about the extended instructions that share this instruction prefix
    InterestBearingMintExtension,
    /// The common instruction prefix for CPI Guard account extension instructions.
    ///
    /// See `extension::cpi_guard::instruction::CpiGuardInstruction` for
    /// further details about the extended instructions that share this instruction prefix
    CpiGuardExtension,
    /// Initialize the permanent delegate on a new mint.
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
    ///
    /// Data expected by this instruction:
    ///   Pubkey for the permanent delegate
    ///
    InitializePermanentDelegate {
        /// Authority that may sign for `Transfer`s and `Burn`s on any account
        #[cfg_attr(feature = "serde-traits", serde(with = "As::<DisplayFromStr>"))]
        delegate: Pubkey,
    },
    /// The common instruction prefix for transfer hook extension instructions.
    ///
    /// See `extension::transfer_hook::instruction::TransferHookInstruction`
    /// for further details about the extended instructions that share this instruction
    /// prefix
    TransferHookExtension,
    /// The common instruction prefix for the confidential transfer fee extension instructions.
    ///
    /// See `extension::confidential_transfer_fee::instruction::ConfidentialTransferFeeInstruction`
    /// for further details about the extended instructions that share this instruction prefix
    ConfidentialTransferFeeExtension,
    /// This instruction is to be used to rescue SOLs sent to any TokenProgram
    /// owned account by sending them to any other account, leaving behind only
    /// lamports for rent exemption.
    ///
    /// 0. `[writable]` Source Account owned by the token program
    /// 1. `[writable]` Destination account
    /// 2. `[signer]` Authority
    /// 3. ..2+M `[signer]` M signer accounts.
    WithdrawExcessLamports,
    /// The common instruction prefix for metadata pointer extension instructions.
    ///
    /// See `extension::metadata_pointer::instruction::MetadataPointerInstruction`
    /// for further details about the extended instructions that share this instruction
    /// prefix
    MetadataPointerExtension,
}
impl<'a> TokenInstruction<'a> {
    /// Unpacks a byte buffer into a [TokenInstruction](enum.TokenInstruction.html).
    pub fn unpack(input: &'a [u8]) -> Result<Self, Error> {

        let (&tag, rest) = input.split_first().ok_or(anyhow!("Invalid Instruction"))?;
        Ok(match tag {
            0 => {
                let (&decimals, rest) = rest.split_first().ok_or(anyhow!("Invalid Instruction - 0"))?;
                let (mint_authority, rest) = Self::unpack_pubkey(rest)?;
                let (freeze_authority, _rest) = Self::unpack_pubkey_option(rest)?;
                Self::InitializeMint {
                    mint_authority,
                    freeze_authority,
                    decimals,
                }
            }
            1 => Self::InitializeAccount,
            2 => {
                let &m = rest.first().ok_or(anyhow!("Invalid Instruction - 2"))?;
                Self::InitializeMultisig { m }
            }
            3 | 4 | 7 | 8 => {
                let amount = rest
                    .get(..U64_BYTES)
                    .and_then(|slice| slice.try_into().ok())
                    .map(u64::from_le_bytes)
                    .ok_or(anyhow!("Invalid Instruction - 3 | 4 | 7 | 8"))?;
                match tag {
                    #[allow(deprecated)]
                    3 => Self::Transfer { amount },
                    4 => Self::Approve { amount },
                    7 => Self::MintTo { amount },
                    8 => Self::Burn { amount },
                    _ => unreachable!(),
                }
            }
            5 => Self::Revoke,
            6 => {
                let (authority_type, rest) = rest
                    .split_first()
                    .ok_or_else(|| anyhow!("Invalid Instruction - 6"))
                    .and_then(|(&t, rest)| Ok((AuthorityType::from(t)?, rest)))?;
                let (new_authority, _rest) = Self::unpack_pubkey_option(rest)?;

                Self::SetAuthority {
                    authority_type,
                    new_authority,
                }
            }
            9 => Self::CloseAccount,
            10 => Self::FreezeAccount,
            11 => Self::ThawAccount,
            12 => {
                let (amount, decimals, _rest) = Self::unpack_amount_decimals(rest)?;
                Self::TransferChecked { amount, decimals }
            }
            13 => {
                let (amount, decimals, _rest) = Self::unpack_amount_decimals(rest)?;
                Self::ApproveChecked { amount, decimals }
            }
            14 => {
                let (amount, decimals, _rest) = Self::unpack_amount_decimals(rest)?;
                Self::MintToChecked { amount, decimals }
            }
            15 => {
                let (amount, decimals, _rest) = Self::unpack_amount_decimals(rest)?;
                Self::BurnChecked { amount, decimals }
            }
            16 => {
                let (owner, _rest) = Self::unpack_pubkey(rest)?;
                Self::InitializeAccount2 { owner }
            }
            17 => Self::SyncNative,
            18 => {
                let (owner, _rest) = Self::unpack_pubkey(rest)?;
                Self::InitializeAccount3 { owner }
            }
            19 => {
                let &m = rest.first().ok_or(anyhow!("Invalid Instruction - 19"))?;
                Self::InitializeMultisig2 { m }
            }
            20 => {
                let (&decimals, rest) = rest.split_first().ok_or(anyhow!("Invalid Instruction - 20"))?;
                let (mint_authority, rest) = Self::unpack_pubkey(rest)?;
                let (freeze_authority, _rest) = Self::unpack_pubkey_option(rest)?;
                Self::InitializeMint2 {
                    mint_authority,
                    freeze_authority,
                    decimals,
                }
            }
            21 => {
                let mut extension_types = vec![];
                for chunk in rest.chunks(size_of::<ExtensionType>()) {
                    extension_types.push(chunk.try_into()?);
                }
                Self::GetAccountDataSize { extension_types }
            }
            22 => Self::InitializeImmutableOwner,
            23 => {
                let (amount, _rest) = Self::unpack_u64(rest)?;
                Self::AmountToUiAmount { amount }
            }
            24 => {
                let ui_amount = std::str::from_utf8(rest).map_err(|_| anyhow!("Invalid Instruction - 24"))?;
                Self::UiAmountToAmount { ui_amount }
            }
            25 => {
                let (close_authority, _rest) = Self::unpack_pubkey_option(rest)?;
                Self::InitializeMintCloseAuthority { close_authority }
            }
            26 => {
                let (instruction, _rest) = TransferFeeInstruction::unpack(rest)?;
                Self::TransferFeeExtension(instruction)
            }
            27 => Self::ConfidentialTransferExtension,
            28 => Self::DefaultAccountStateExtension,
            29 => {
                let mut extension_types = vec![];
                for chunk in rest.chunks(size_of::<ExtensionType>()) {
                    extension_types.push(chunk.try_into()?);
                }
                Self::Reallocate { extension_types }
            }
            30 => Self::MemoTransferExtension,
            31 => Self::CreateNativeMint,
            32 => Self::InitializeNonTransferableMint,
            33 => Self::InterestBearingMintExtension,
            34 => Self::CpiGuardExtension,
            35 => {
                let (delegate, _rest) = Self::unpack_pubkey(rest)?;
                Self::InitializePermanentDelegate { delegate }
            }
            36 => Self::TransferHookExtension,
            37 => Self::ConfidentialTransferFeeExtension,
            38 => Self::WithdrawExcessLamports,
            39 => Self::MetadataPointerExtension,
            _ => return Err(anyhow!("Invalid Instruction - unpack didn't match any tag value: {}", tag)),
        })
    }


    pub(crate) fn unpack_pubkey(input: &[u8]) -> Result<(Pubkey, &[u8]), Error> {
        let pk = input
            .get(..PUBKEY_BYTES)
            .and_then(|x| Pubkey::try_from(x).ok())
            .ok_or(anyhow!("Unable to unpack pubkey from bytes"))?;
        Ok((pk, &input[PUBKEY_BYTES..]))
    }

    pub(crate) fn unpack_pubkey_option(
        input: &[u8],
    ) -> Result<(COption<Pubkey>, &[u8]), Error> {
        match input.split_first() {
            Option::Some((&0, rest)) => Ok((COption::None, rest)),
            Option::Some((&1, rest)) => {
                let (pk, rest) = Self::unpack_pubkey(rest)?;
                Ok((COption::Some(pk), rest))
            }
            _ => Err(anyhow!("unable to unpack pubkey option")),
        }
    }


    pub(crate) fn unpack_u16(input: &[u8]) -> Result<(u16, &[u8]), Error> {
        let value = input
            .get(..U16_BYTES)
            .and_then(|slice| slice.try_into().ok())
            .map(u16::from_le_bytes)
            .ok_or(anyhow!("Unable to unpack u16"))?;
        Ok((value, &input[U16_BYTES..]))
    }

    pub(crate) fn unpack_u64(input: &[u8]) -> Result<(u64, &[u8]), Error> {
        let value = input
            .get(..U64_BYTES)
            .and_then(|slice| slice.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or(anyhow!("Unable to unpack u64"))?;
        Ok((value, &input[U64_BYTES..]))
    }

    pub(crate) fn unpack_amount_decimals(input: &[u8]) -> Result<(u64, u8, &[u8]), Error> {
        let (amount, rest) = Self::unpack_u64(input)?;
        let (&decimals, rest) = rest.split_first().ok_or(anyhow!("Unable to unpack amount decimals"))?;
        Ok((amount, decimals, rest))
    }
}

/// Specifies the authority type for SetAuthority instructions
#[repr(u8)]
#[cfg_attr(feature = "serde-traits", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde-traits", serde(rename_all = "camelCase"))]
#[derive(Clone, Debug, PartialEq)]
pub enum AuthorityType {
    /// Authority to mint new tokens
    MintTokens,
    /// Authority to freeze any account associated with the Mint
    FreezeAccount,
    /// Owner of a given token account
    AccountOwner,
    /// Authority to close a token account
    CloseAccount,
    /// Authority to set the transfer fee
    TransferFeeConfig,
    /// Authority to withdraw withheld tokens from a mint
    WithheldWithdraw,
    /// Authority to close a mint account
    CloseMint,
    /// Authority to set the interest rate
    InterestRate,
    /// Authority to transfer or burn any tokens for a mint
    PermanentDelegate,
    /// Authority to update confidential transfer mint and aprove accounts for confidential
    /// transfers
    ConfidentialTransferMint,
    /// Authority to set the transfer hook program id
    TransferHookProgramId,
    /// Authority to set the withdraw withheld authority encryption key
    ConfidentialTransferFeeConfig,
    /// Authority to set the metadata address
    MetadataPointer,
}

impl AuthorityType {
    fn from(index: u8) -> Result<Self, Error> {
        match index {
            0 => Ok(AuthorityType::MintTokens),
            1 => Ok(AuthorityType::FreezeAccount),
            2 => Ok(AuthorityType::AccountOwner),
            3 => Ok(AuthorityType::CloseAccount),
            4 => Ok(AuthorityType::TransferFeeConfig),
            5 => Ok(AuthorityType::WithheldWithdraw),
            6 => Ok(AuthorityType::CloseMint),
            7 => Ok(AuthorityType::InterestRate),
            8 => Ok(AuthorityType::PermanentDelegate),
            9 => Ok(AuthorityType::ConfidentialTransferMint),
            10 => Ok(AuthorityType::TransferHookProgramId),
            11 => Ok(AuthorityType::ConfidentialTransferFeeConfig),
            12 => Ok(AuthorityType::MetadataPointer),
            _ => Err(anyhow!("Invalid Instruction - Invalid AuthorityType with index {}", index)),
        }
    }
}


/// Extensions that can be applied to mints or accounts.  Mint extensions must only be
/// applied to mint accounts, and account extensions must only be applied to token holding
/// accounts.
#[repr(u16)]
#[cfg_attr(feature = "serde-traits", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde-traits", serde(rename_all = "camelCase"))]
#[derive(Clone, Copy, Debug, PartialEq, TryFromPrimitive, IntoPrimitive)]
pub enum ExtensionType {
    /// Used as padding if the account size would otherwise be 355, same as a multisig
    Uninitialized,
    /// Includes transfer fee rate info and accompanying authorities to withdraw and set the fee
    TransferFeeConfig,
    /// Includes withheld transfer fees
    TransferFeeAmount,
    /// Includes an optional mint close authority
    MintCloseAuthority,
    /// Auditor configuration for confidential transfers
    ConfidentialTransferMint,
    /// State for confidential transfers
    ConfidentialTransferAccount,
    /// Specifies the default Account::state for new Accounts
    DefaultAccountState,
    /// Indicates that the Account owner authority cannot be changed
    ImmutableOwner,
    /// Require inbound transfers to have memo
    MemoTransfer,
    /// Indicates that the tokens from this mint can't be transfered
    NonTransferable,
    /// Tokens accrue interest over time,
    InterestBearingConfig,
    /// Locks privileged token operations from happening via CPI
    CpiGuard,
    /// Includes an optional permanent delegate
    PermanentDelegate,
    /// Indicates that the tokens in this account belong to a non-transferable mint
    NonTransferableAccount,
    /// Mint requires a CPI to a program implementing the "transfer hook" interface
    TransferHook,
    /// Indicates that the tokens in this account belong to a mint with a transfer hook
    TransferHookAccount,
    /// Includes encrypted withheld fees and the encryption public that they are encrypted under
    ConfidentialTransferFeeConfig,
    /// Includes confidential withheld transfer fees
    ConfidentialTransferFeeAmount,
    /// Mint contains a pointer to another account (or the same account) that holds metadata
    MetadataPointer,
    /// Mint contains token-metadata
    TokenMetadata,
    /// Test variable-length mint extension
    #[cfg(test)]
    VariableLenMintTest = u16::MAX - 2,
    /// Padding extension used to make an account exactly Multisig::LEN, used for testing
    #[cfg(test)]
    AccountPaddingTest,
    /// Padding extension used to make a mint exactly Multisig::LEN, used for testing
    #[cfg(test)]
    MintPaddingTest,
}
impl TryFrom<&[u8]> for ExtensionType {
    type Error = Error;
    fn try_from(a: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(u16::from_le_bytes(
            a.try_into().map_err(|_| anyhow!("ExtensionType - Invalid extension type from byte"))?,
        ))
            .map_err(|_| anyhow!("ExtensionType - try from - Invalid account data"))
    }
}
impl From<ExtensionType> for [u8; 2] {
    fn from(a: ExtensionType) -> Self {
        u16::from(a).to_le_bytes()
    }
}
