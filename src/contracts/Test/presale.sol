// SPDX-License-Identifier: MIT
pragma solidity 0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract Presale is ReentrancyGuard {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;
    
    IERC20 public token;
    IERC20 public usdc;

    bool public paused = false;
    bool public finish = false;

    uint256 public startTimeStamp;
    uint256 public presaleDays;
    uint256 public constant DAY = 1 days;

    uint256 public presaleTokensSold = 0;
    uint256 public usdcReceived = 0;
    // $1 = 20 Tokens @ 0.05
    uint256 public constant TOKEN_PER_USDC = 20000000000000;
    // $1 = 100 Tokens @ 0.01
    // uint256 public constant TOKEN_PER_USDC = 100000000000000;	
    uint256 public constant HARD_CAP = 1000000000 ether;

    uint16 public referralCommissionRate = 500; // 5%

    mapping (address => uint256) public tokenBalances;

    event Purchase(address indexed _address, uint256 _amount, uint256 _tokensAmount);
    event IncreasePresaleOneMoreDay();
    event Paused();
    event Started();
    event Finish();

    address public owner;

    modifier onlyOwner() {
        require(owner == msg.sender, "Ownable: caller is not the owner");
        _;
    }

    constructor (
        address _token,
        address _usdc,
        uint256 _startTimestamp,
        uint256 _presaleDays
    ) public {
        owner = msg.sender;
        token = IERC20(_token);
        usdc = IERC20(_usdc);
        startTimeStamp = _startTimestamp;
        presaleDays = _presaleDays;
    }

    function purchase (uint256 _amount) public {
        require(!paused, "Presale: paused");
        require(_amount > 0, "Presale: amount should greater than 0");
        require(block.timestamp >= startTimeStamp, "Presale: presale not start yet");
        require(block.timestamp <= startTimeStamp + presaleDays * DAY, "Presale: presale had already finished");

        address buyer = msg.sender;
        uint256 tokensAmount = _amount.mul(TOKEN_PER_USDC);
        require (presaleTokensSold +  tokensAmount <= HARD_CAP, "Presale: hardcap reached");

        usdc.safeTransferFrom(msg.sender, address(this), _amount);
        tokenBalances[buyer] = tokenBalances[buyer].add(tokensAmount);
        presaleTokensSold = presaleTokensSold.add(tokensAmount);
        usdcReceived = usdcReceived.add(_amount);

        token.safeTransfer(msg.sender, tokensAmount);

        emit Purchase(buyer, _amount, tokensAmount);
    }

    function increaseOneMoreDay() external onlyOwner {
        presaleDays += 1;
        emit IncreasePresaleOneMoreDay();
    }

    function setPause() external onlyOwner {
        paused = true;
        emit Paused();
    }

    function setStart() external onlyOwner {
        paused = false;
        emit Started();
    }

    function setFinish() external onlyOwner {
        finish = true;
        emit Finish();
    }

    function withdrawFunds() external onlyOwner {
        usdc.safeTransfer(msg.sender, usdc.balanceOf(address(this)));
    }

    function withdrawUnsoldToken() external onlyOwner {
        require(finish, "withdrawUnsoldToken: not finish");
        uint256 amount = token.balanceOf(address(this)) - presaleTokensSold;
        token.safeTransfer(msg.sender, amount);
    }
}