// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AmadeusLightClient} from "./AmadeusLightClient.sol";
import {Hbsmt} from "./Hbsmt.sol";
import {Order} from "./Order.sol";
import {WAMA} from "./WAMA.sol";
import {Decimal} from "./Decimal.sol";

/// EVM side of the Amadeus bridge, the same on every EVM chain (Amadeus: ex/native/rdb/src/consensus/bic/bridge.rs).
/// AMA is native to Amadeus: it arrives here as wAMA (minted once the Amadeus order is
/// proven) and leaves by burning wAMA; Amadeus releases it from escrow after proving
/// `orders[nonce]` in this contract's storage. No fee here: Amadeus burns 0.1 bp on its sends,
/// so Amadeus orders arrive with output = amount - fee and orders from here carry the full amount.
/// Delivery: orders with gasDropFee = 0 are claimed by their recipient. Otherwise anyone may
/// deliver: the deliverer gets gasDropFee (out of the order) and passes gasDrop of the
/// destination's gas coin to the recipient (this chain's, as msg.value).
contract AmaBridge {
    /// storage slot 0: Amadeus proves `orders[nonce] == keccak256(order)` at this slot
    mapping(uint64 => bytes32) public orders;
    uint64 public nonce;
    mapping(uint64 => bool) public received;
    mapping(uint256 => uint256) public sentPerDay;
    mapping(uint256 => uint256) public receivedPerDay;
    bool public sendPaused;
    bool public receivePaused;

    uint256 public constant CAP_PER_DAY = 10_000_000 * 1e9;
    /// gas a gas-drop transfer may use: an account or a wallet's receive, nothing more
    uint256 public constant GAS_DROP_GAS = 30_000;
    bytes32 public immutable localChain;
    bytes32 public immutable amadeusChain;
    address public immutable admin;
    AmadeusLightClient public immutable lightClient;
    WAMA public immutable wama;

    event OrderCreated(uint64 indexed nonce, bytes order);
    event OrderReceived(uint64 indexed nonce, address indexed recipient, uint256 amount, address deliverer, uint256 gasDrop);

    error Paused();
    error CapReached();
    error BadAmount();
    error BadAddress();
    error WrongChain();
    error WrongCoin();
    error Unsupported();
    error AlreadyReceived();
    error NotProven();
    error OnlyAdmin();
    error BadGasDrop();

    /// `wama_` must be deployed with this bridge as its minter (see script/Deploy.s.sol).
    /// orders start after `lastNonce` (nonzero only when replacing a deployment Amadeus already received from)
    constructor(AmadeusLightClient lightClient_, WAMA wama_, bytes32 localChain_, bytes32 amadeusChain_, address admin_, uint64 lastNonce) {
        nonce = lastNonce;
        lightClient = lightClient_;
        wama = wama_;
        localChain = localChain_;
        amadeusChain = amadeusChain_;
        admin = admin_;
    }

    function amadeusFee(uint256 amount) public pure returns (uint256) {
        return amount / 100_000;
    }

    /// burn `amount` wAMA and create an order for AMA to `recipient` (48-byte Amadeus key) on Amadeus.
    /// gasDrop (AMA base units) and gasDropFee (out of the amount) ask a relay to deliver it
    function send(uint128 amount, bytes calldata recipient, bytes calldata refundTo, uint64 fillDeadline, uint128 gasDrop, uint128 gasDropFee)
        external returns (uint64 n)
    {
        if (sendPaused) revert Paused();
        if (amount == 0 || gasDropFee > amount) revert BadAmount();
        //a compressed G1 key: compression flag set, infinity flag clear
        if (recipient.length != 48 || uint8(recipient[0]) & 0xc0 != 0x80 || refundTo.length > 48) revert BadAddress();
        if ((sentPerDay[block.timestamp / 1 days] += amount) > CAP_PER_DAY) revert CapReached();
        wama.burn(msg.sender, amount);

        n = ++nonce;
        Order.Data memory o;
        o.srcChain = localChain;
        o.nonce = n;
        o.sender = abi.encodePacked(msg.sender);
        o.refundTo = refundTo.length == 0 ? o.sender : refundTo;
        o.srcCoin = abi.encodePacked(address(wama));
        o.amount = amount;
        o.dstChain = amadeusChain;
        o.dstCoin = "AMA";
        o.recipient = recipient;
        o.outputAmount = amount - gasDropFee;
        o.fillDeadline = fillDeadline;
        o.gasDrop = gasDrop;
        o.gasDropFee = gasDropFee;
        bytes memory packed = Order.pack(o);
        orders[n] = keccak256(packed);
        emit OrderCreated(n, packed);
    }

    /// msg.value must be the order's gasDrop, which goes to the recipient (0 when the recipient claims)
    function receiveOrder(bytes calldata order, uint64 height, Hbsmt.Proof calldata proof) external payable {
        deliver(order, height, proof);
    }

    function receiveOrderWithConsensus(
        bytes calldata claim, bytes calldata mask, bytes calldata sig, bytes calldata roster,
        bytes calldata order, Hbsmt.Proof calldata proof
    ) external payable {
        uint64 height = uint64(bytes8(claim[0:8]));
        if (lightClient.stateRoot(height) == bytes32(0)) lightClient.submitConsensus(claim, mask, sig, roster);
        deliver(order, height, proof);
    }

    function deliver(bytes calldata order, uint64 height, Hbsmt.Proof calldata proof) private {
        if (receivePaused) revert Paused();
        Order.Data memory o = Order.unpack(order);
        if (o.srcChain != amadeusChain || o.dstChain != localChain) revert WrongChain();
        if (keccak256(o.srcCoin) != keccak256("AMA") || keccak256(o.dstCoin) != keccak256(abi.encodePacked(address(wama)))) revert WrongCoin();
        if (uint256(o.outputAmount) + o.gasDropFee != o.amount - amadeusFee(o.amount)) revert BadAmount();
        if (o.exclusiveFiller.length != 0 || o.message.length != 0) revert Unsupported();
        if (o.recipient.length != 20) revert BadAddress();
        address to = address(bytes20(o.recipient));
        //a recipient claiming its own order owes itself no gas drop, so no gasDrop can lock an order
        if (msg.value != (msg.sender == to ? 0 : o.gasDrop)) revert BadGasDrop();
        if (received[o.nonce]) revert AlreadyReceived();
        bytes memory key = bytes.concat("bic:bridge:order:", Decimal.pad(o.nonce, 20));
        if (!lightClient.proven(height, "bic", key, order, proof)) revert NotProven();

        received[o.nonce] = true;
        if ((receivedPerDay[block.timestamp / 1 days] += o.amount) > CAP_PER_DAY) revert CapReached();
        wama.mint(to, o.outputAmount);
        if (o.gasDropFee > 0) wama.mint(msg.sender, o.gasDropFee);
        //a recipient that refuses the gas drop must not block the order: it goes back to the deliverer.
        //Both calls get GAS_DROP_GAS only, so a recipient contract cannot spend the deliverer's gas
        //and a delivery always completes within the gas it was priced for
        if (msg.value > 0) {
            (bool ok,) = to.call{value: msg.value, gas: GAS_DROP_GAS}("");
            if (!ok) {
                (ok,) = msg.sender.call{value: msg.value, gas: GAS_DROP_GAS}("");
                if (!ok) revert BadGasDrop();
            }
        }
        emit OrderReceived(o.nonce, to, o.outputAmount, msg.sender, msg.value);
    }

    function pause(bool send_, bool receive_) external {
        if (msg.sender != admin) revert OnlyAdmin();
        sendPaused = send_;
        receivePaused = receive_;
    }
}
