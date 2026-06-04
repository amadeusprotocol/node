defmodule HTTP.Prometheus do
  import Bitwise

  @min_token_len 16

  def authorized?(headers) do
    token = Application.fetch_env!(:ama, :prometheus_token)
    cond do
      not is_binary(token) or byte_size(token) < @min_token_len -> false
      true ->
        presented = headers["authorization"]
        is_binary(presented) and secure_compare("Bearer #{token}", presented)
    end
  end

  defp secure_compare(a, b) when is_binary(a) and is_binary(b) do
    byte_size(a) == byte_size(b) and constant_time_eq(a, b, 0)
  end
  defp constant_time_eq(<<x, a::binary>>, <<y, b::binary>>, acc),
    do: constant_time_eq(a, b, bor(acc, bxor(x, y)))
  defp constant_time_eq(<<>>, <<>>, acc), do: acc == 0

  def health() do
    tip = DB.Chain.tip_entry()
    status = if tip && tip.header.height > 0, do: "ok", else: "initializing"
    """
    # HELP amadeus_health Node health status (1 = healthy, 0 = unhealthy)
    # TYPE amadeus_health gauge
    amadeus_health{status="#{status}"} #{if status == "ok", do: 1, else: 0}
    """
  end

  def metrics_stats() do
    stats = API.Chain.stats()

    """
    # HELP amadeus_block_height Current blockchain height
    # TYPE amadeus_block_height counter
    amadeus_block_height #{stats.height}

    # HELP amadeus_tx_pool_size Number of transactions in mempool
    # TYPE amadeus_tx_pool_size gauge
    amadeus_tx_pool_size #{stats.tx_pool_size}

    # HELP amadeus_txs_per_second Transactions per second (rolling 100-block average)
    # TYPE amadeus_txs_per_second gauge
    amadeus_txs_per_second #{format_float(stats.txs_per_sec)}

    # HELP amadeus_pflops Estimated network petaflops
    # TYPE amadeus_pflops gauge
    amadeus_pflops #{format_float(stats.pflops)}

    # HELP amadeus_circulating_supply Circulating AMA supply
    # TYPE amadeus_circulating_supply gauge
    amadeus_circulating_supply #{format_float(stats.circulating)}

    # HELP amadeus_burned_ama Total AMA burned
    # TYPE amadeus_burned_ama counter
    amadeus_burned_ama #{format_float(stats.burned)}

    # HELP amadeus_total_supply_y3 Total supply at year 3
    # TYPE amadeus_total_supply_y3 gauge
    amadeus_total_supply_y3 #{stats.total_supply_y3}

    # HELP amadeus_total_supply_y30 Total supply at year 30
    # TYPE amadeus_total_supply_y30 gauge
    amadeus_total_supply_y30 #{stats.total_supply_y30}

    # HELP amadeus_epoch_emission Emission for current epoch
    # TYPE amadeus_epoch_emission gauge
    amadeus_epoch_emission #{format_float(stats.emission_for_epoch)}

    # HELP amadeus_difficulty_bits Current difficulty in bits
    # TYPE amadeus_difficulty_bits gauge
    amadeus_difficulty_bits #{stats.diff_bits}
    """
  end

  def metrics_kpi() do
    kpi = API.Chain.kpi()

    """
    # HELP amadeus_total_transactions Total transaction count
    # TYPE amadeus_total_transactions counter
    amadeus_total_transactions #{kpi.total_tx}

    # HELP amadeus_unique_active_wallets Unique active wallets
    # TYPE amadeus_unique_active_wallets gauge
    amadeus_unique_active_wallets #{kpi.uaw}

    # HELP amadeus_active_peers Number of connected peers
    # TYPE amadeus_active_peers gauge
    amadeus_active_peers #{kpi.active_peers}

    # HELP amadeus_active_validators Number of active validator keys
    # TYPE amadeus_active_validators gauge
    amadeus_active_validators #{kpi.active_validator_keys}

    # HELP amadeus_fees_paid_ama Total fees paid in AMA
    # TYPE amadeus_fees_paid_ama counter
    amadeus_fees_paid_ama #{format_float(kpi.fees_paid)}

    # HELP amadeus_block_time_ms Block time in milliseconds
    # TYPE amadeus_block_time_ms gauge
    amadeus_block_time_ms #{kpi.block_time}
    """
  end

  def metrics_validators() do
    scores = API.Epoch.score()

    header = """
    # HELP amadeus_validator_solutions Validator solution count in current epoch
    # TYPE amadeus_validator_solutions gauge
    """

    metrics = Enum.map(scores, fn [pk, count] ->
      "amadeus_validator_solutions{validator=\"#{pk}\"} #{count}"
    end)
    |> Enum.join("\n")

    header <> metrics <> "\n"
  end

  def metrics_all() do
    [
      metrics_stats(),
      metrics_kpi(),
      metrics_validators()
    ]
    |> Enum.join("\n")
  end

  defp format_float(value) when is_float(value), do: Float.round(value, 6)
  defp format_float(value), do: value
end
