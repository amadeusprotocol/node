defmodule BLS12AggSigSecurityTest do
  use ExUnit.Case, async: true

  test "rejects set padding bits and non-canonical mask lengths" do
    assert BLS12AggSig.validate_mask(<<0b10000000>>, 2) == :ok

    assert BLS12AggSig.validate_mask(<<0b10111111>>, 2) ==
             {:error, :mask_nonzero_padding}

    assert BLS12AggSig.validate_mask(<<0b10000000, 0>>, 2) ==
             {:error, :mask_wrong_size}

    assert BLS12AggSig.validate_mask(<<1::1>>, 1) ==
             {:error, :mask_not_byte_aligned}
  end

  test "padding bits can never become phantom signers" do
    trainers = [<<1>>, <<2>>]
    malicious_mask = <<0b10111111>>

    assert BLS12AggSig.unmask_trainers(trainers, malicious_mask, bit_size(malicious_mask)) == [
             <<1>>
           ]

    assert BLS12AggSig.score(trainers, malicious_mask, bit_size(malicious_mask)) == 0.5
    refute BLS12AggSig.quorum?(1, length(trainers))
  end

  test "quorum uses exact integer arithmetic" do
    assert BLS12AggSig.quorum?(67, 100)
    refute BLS12AggSig.quorum?(66, 100)
    refute BLS12AggSig.quorum?(2, 3)
    refute BLS12AggSig.quorum?(1, 0)
  end
end
