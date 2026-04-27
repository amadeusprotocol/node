defmodule BIC.Coin do
    @decimals 9
    @burn_address :binary.copy(<<0>>, 48)

    def to_flat(coins) when is_integer(coins) do
        coins * 1_000_000_000
    end

    def to_cents(coins) when is_integer(coins) do
        coins *    10_000_000
    end

    def to_tenthousandth(coins) when is_integer(coins) do
        coins *       100_000
    end

    def from_flat(coins) do
        Float.round(coins / 1_000_000_000, 9)
    end

    def burn_address() do
        @burn_address
    end
end
