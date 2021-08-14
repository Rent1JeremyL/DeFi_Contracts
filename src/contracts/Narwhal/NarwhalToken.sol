// SPDX-License-Identifier: MIT
pragma solidity 0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

// BottlenoseToken with Governance.
contract NarwhalToken is ERC20, Ownable, ERC20Burnable {
    using SafeMath for uint256;
	// Burn address
	address public constant BURN_ADDRESS = 0x000000000000000000000000000000000000dEaD;
    uint256 private _cap;
    
	// Max transfer amount rate in basis points. (default is 1% of total supply)
	uint16 public maxTransferAmountRate = 100;
	// Min value of the max transfer amount rate. (0.5%)
	uint16 public constant maxTransferMinRate = 50;

	// Addresses that excluded from antiWhale
	mapping(address => bool) private _excludedFromAntiWhale;

    // Is the transfer enabled? (False by default)
    bool public isTransactionEnabled = false;

    // Blacklisted addresses
    mapping(address => bool) private blackList;
	// anti-bot end block
	uint256 public antiBotBlock;
    // The duration that the anti-bot function last: 200 blocks ~  10mins (from launch)
    uint256 public constant ANTI_BOT_TIME = 200;

	// Events
	event OperatorTransferred(address indexed previousOperator, address indexed newOperator);
	event MaxTransferAmountRateUpdated(address indexed operator, uint256 previousRate, uint256 newRate);

	modifier antiWhale(address sender, address recipient, uint256 amount) {
		if (maxTransferAmount() > 0) {
			if (_excludedFromAntiWhale[sender] == false && _excludedFromAntiWhale[recipient] == false) {
				require(amount <= maxTransferAmount(), "TOKEN::antiWhale: Transfer amount exceeds the maxTransferAmount");
			}
		}
		_;
	}

    /**
     * @dev Blocks transaction before launch, so can inject liquidity before launch
     */
    modifier blockTransaction(address sender) { 
        if (isTransactionEnabled == false) { 
            require(sender == owner(), "TOKEN::blockTransaction: Transfers can only be done by operator."); 
        }
        _; 
    }

	modifier antiBot(address recipient) {
		if (isTransactionEnabled && block.number <= antiBotBlock) {
			require(balanceOf(recipient) <= maxTransferAmount(), "TOKEN:: antiBot: Suspected bot activity");
		}
        _; 
	}


	/**
	 * @notice Constructs the BottlenoseToken contract.
	 */
	constructor(uint256 nCap) public ERC20("Narwhal Token", "NAR") {
		require(nCap > 0, "GovernanceToken: cap is 0");
        _cap = nCap;
		
		_excludedFromAntiWhale[msg.sender] = true;
		_excludedFromAntiWhale[address(0)] = true;
		_excludedFromAntiWhale[address(this)] = true;
		_excludedFromAntiWhale[BURN_ADDRESS] = true;
		
		// Setup LP pools wtih 10,000 tokens @ $2k for 0.2
        _mint(msg.sender, 10000000000000000000000);
	}

	/// @notice Creates `_amount` token to `_to`. Must only be called by the owner (MasterChef).
	function mint(address _to, uint256 _amount) public onlyOwner {
        require(ERC20.totalSupply() + _amount <= cap(), "GovernanceToken: cap exceeded");
        
		_mint(_to, _amount);
		_moveDelegates(address(0), _delegates[_to], _amount);
	}

	/// @dev overrides transfer function to meet tokenomics of BTN
	function _transfer(address sender, address recipient, uint256 amount) internal virtual override 
										blockTransaction(sender) antiWhale(sender, recipient, amount) antiBot(recipient) {
        require(blackList[sender] == false,"TOKEN::transfer: You're blacklisted");

		super._transfer(sender, recipient, amount);

	}

	/**
	 * @dev Returns the max transfer amount.
	 */
	function maxTransferAmount() public view returns (uint256) {
		return totalSupply().mul(maxTransferAmountRate).div(10000);
	}

	/**
	 * @dev Returns the address is excluded from antiWhale or not.
	 */
	function isExcludedFromAntiWhale(address _account) public view returns (bool) {
		return _excludedFromAntiWhale[_account];
	}

	/**
	 * @dev Update the max transfer amount rate.
	 * Can only be called by the current operator.
	 */
	function updateMaxTransferAmountRate(uint16 _maxTransferAmountRate) public onlyOwner {
		require(_maxTransferAmountRate <= 10000, "TOKEN::updateMaxTransferAmountRate: Max transfer amount rate must not exceed the maximum rate.");
		require(_maxTransferAmountRate >= maxTransferMinRate,"TOKEN::updateMaxTransferAmountRate: Max transfer amount rate must be grater than min rate");
		emit MaxTransferAmountRateUpdated(msg.sender, maxTransferAmountRate, _maxTransferAmountRate);
		maxTransferAmountRate = _maxTransferAmountRate;
	}

	/**
	 * @dev Exclude or include an address from antiWhale.
	 * Can only be called by the current operator.
	 */
	function setExcludedFromAntiWhale(address _account, bool _excluded) public onlyOwner {
		_excludedFromAntiWhale[_account] = _excluded;
	}

    /**
     * @dev Enable transactions.
     * Can only be called once by the current operator.
     */
    function enableTransaction() public onlyOwner {
		require(isTransactionEnabled == false,"TOKEN::enableTransaction: This meothod can only be called once");
        isTransactionEnabled = true;
		antiBotBlock = block.number.add(ANTI_BOT_TIME);
    }

    /**
     * @dev Exclude or include an address from blackList.
     */
    function addToBlackList(address _account, bool _excluded) public onlyOwner {
        blackList[_account] = _excluded;
    }

    /**
     * @dev Returns the address is excluded from blackList or not.
     */
    function isBlackListed(address _account) public view returns (bool) {
        return blackList[_account];
    }



	// Copied and modified from YAM code:
	// https://github.com/yam-finance/yam-protocol/blob/master/contracts/token/YAMGovernanceStorage.sol
	// https://github.com/yam-finance/yam-protocol/blob/master/contracts/token/YAMGovernance.sol
	// Which is copied and modified from COMPOUND:
	// https://github.com/compound-finance/compound-protocol/blob/master/contracts/Governance/Comp.sol

	/// @dev A record of each accounts delegate
	mapping(address => address) internal _delegates;

	/// @notice A checkpoint for marking number of votes from a given block
	struct Checkpoint {
		uint32 fromBlock;
		uint256 votes;
	}

	/// @notice A record of votes checkpoints for each account, by index
	mapping(address => mapping(uint32 => Checkpoint)) public checkpoints;

	/// @notice The number of checkpoints for each account
	mapping(address => uint32) public numCheckpoints;

	/// @notice The EIP-712 typehash for the contract's domain
	bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");

	/// @notice The EIP-712 typehash for the delegation struct used by the contract
	bytes32 public constant DELEGATION_TYPEHASH = keccak256("Delegation(address delegatee,uint256 nonce,uint256 expiry)");

	/// @notice A record of states for signing / validating signatures
	mapping(address => uint256) public nonces;

	/// @notice An event thats emitted when an account changes its delegate
	event DelegateChanged(address indexed delegator, address indexed fromDelegate, address indexed toDelegate);

	/// @notice An event thats emitted when a delegate account's vote balance changes
	event DelegateVotesChanged(address indexed delegate, uint256 previousBalance, uint256 newBalance);
    /**
     * @dev Returns the cap on the token's total supply.
     */
    function cap() public view returns (uint256) {
        return _cap;
    }

	/**
	 * @notice Delegate votes from `msg.sender` to `delegatee`
	 * @param delegator The address to get delegatee for
	 */
	function delegates(address delegator) external view returns (address) {
		return _delegates[delegator];
	}

	/**
	 * @notice Delegate votes from `msg.sender` to `delegatee`
	 * @param delegatee The address to delegate votes to
	 */
	function delegate(address delegatee) external {
		return _delegate(msg.sender, delegatee);
	}

	/**
	 * @notice Delegates votes from signatory to `delegatee`
	 * @param delegatee The address to delegate votes to
	 * @param nonce The contract state required to match the signature
	 * @param expiry The time at which to expire the signature
	 * @param v The recovery byte of the signature
	 * @param r Half of the ECDSA signature pair
	 * @param s Half of the ECDSA signature pair
	 */
	function delegateBySig(
		address delegatee,
		uint256 nonce,
		uint256 expiry,
		uint8 v,
		bytes32 r,
		bytes32 s
	) external {
		bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name())), getChainId(), address(this)));

		bytes32 structHash = keccak256(abi.encode(DELEGATION_TYPEHASH, delegatee, nonce, expiry));

		bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

		address signatory = ecrecover(digest, v, r, s);
		require(signatory != address(0), "TOKEN::delegateBySig: invalid signature");
		require(nonce == nonces[signatory]++, "TOKEN::delegateBySig: invalid nonce");
		require(block.timestamp <= expiry, "TOKEN::delegateBySig: signature expired");
		return _delegate(signatory, delegatee);
	}

	/**
	 * @notice Gets the current votes balance for `account`
	 * @param account The address to get votes balance
	 * @return The number of current votes for `account`
	 */
	function getCurrentVotes(address account) external view returns (uint256) {
		uint32 nCheckpoints = numCheckpoints[account];
		return nCheckpoints > 0 ? checkpoints[account][nCheckpoints - 1].votes : 0;
	}

	/**
	 * @notice Determine the prior number of votes for an account as of a block number
	 * @dev Block number must be a finalized block or else this function will revert to prevent misinformation.
	 * @param account The address of the account to check
	 * @param blockNumber The block number to get the vote balance at
	 * @return The number of votes the account had as of the given block
	 */
	function getPriorVotes(address account, uint256 blockNumber) external view returns (uint256) {
		require(blockNumber < block.number, "TOKEN::getPriorVotes: not yet determined");

		uint32 nCheckpoints = numCheckpoints[account];
		if (nCheckpoints == 0) {
			return 0;
		}

		// First check most recent balance
		if (checkpoints[account][nCheckpoints - 1].fromBlock <= blockNumber) {
			return checkpoints[account][nCheckpoints - 1].votes;
		}

		// Next check implicit zero balance
		if (checkpoints[account][0].fromBlock > blockNumber) {
			return 0;
		}

		uint32 lower = 0;
		uint32 upper = nCheckpoints - 1;
		while (upper > lower) {
			uint32 center = upper - (upper - lower) / 2; // ceil, avoiding overflow
			Checkpoint memory cp = checkpoints[account][center];
			if (cp.fromBlock == blockNumber) {
				return cp.votes;
			} else if (cp.fromBlock < blockNumber) {
				lower = center;
			} else {
				upper = center - 1;
			}
		}
		return checkpoints[account][lower].votes;
	}

	function _delegate(address delegator, address delegatee) internal {
		address currentDelegate = _delegates[delegator];
		uint256 delegatorBalance = balanceOf(delegator); // balance of underlying BTNs (not scaled);
		_delegates[delegator] = delegatee;

		emit DelegateChanged(delegator, currentDelegate, delegatee);

		_moveDelegates(currentDelegate, delegatee, delegatorBalance);
	}

	function _moveDelegates(
		address srcRep,
		address dstRep,
		uint256 amount
	) internal {
		if (srcRep != dstRep && amount > 0) {
			if (srcRep != address(0)) {
				// decrease old representative
				uint32 srcRepNum = numCheckpoints[srcRep];
				uint256 srcRepOld = srcRepNum > 0 ? checkpoints[srcRep][srcRepNum - 1].votes : 0;
				uint256 srcRepNew = srcRepOld.sub(amount);
				_writeCheckpoint(srcRep, srcRepNum, srcRepOld, srcRepNew);
			}

			if (dstRep != address(0)) {
				// increase new representative
				uint32 dstRepNum = numCheckpoints[dstRep];
				uint256 dstRepOld = dstRepNum > 0 ? checkpoints[dstRep][dstRepNum - 1].votes : 0;
				uint256 dstRepNew = dstRepOld.add(amount);
				_writeCheckpoint(dstRep, dstRepNum, dstRepOld, dstRepNew);
			}
		}
	}

	function _writeCheckpoint(
		address delegatee,
		uint32 nCheckpoints,
		uint256 oldVotes,
		uint256 newVotes
	) internal {
		uint32 blockNumber = safe32(block.number, "TOKEN::_writeCheckpoint: block number exceeds 32 bits");

		if (nCheckpoints > 0 && checkpoints[delegatee][nCheckpoints - 1].fromBlock == blockNumber) {
			checkpoints[delegatee][nCheckpoints - 1].votes = newVotes;
		} else {
			checkpoints[delegatee][nCheckpoints] = Checkpoint(blockNumber, newVotes);
			numCheckpoints[delegatee] = nCheckpoints + 1;
		}

		emit DelegateVotesChanged(delegatee, oldVotes, newVotes);
	}

	function safe32(uint256 n, string memory errorMessage) internal pure returns (uint32) {
		require(n < 2**32, errorMessage);
		return uint32(n);
	}

	function getChainId() internal view returns (uint256) {
		uint256 chainId;
		assembly {
			chainId := chainid()
		}
		return chainId;
	}
}