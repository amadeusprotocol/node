defmodule ValidatorSet do
  @moduledoc """
  Bitmap indices use the immutable epoch roster; scheduling uses active keys.
  A set is always the roster plus a canonical, MSB-first active mask; a record
  still stored as a legacy list reads as an all-active roster.
  """

  def normalize(validators) when is_list(validators) do
    size = length(validators)
    %{validators: validators, mask_active: Util.pad_bitstring_to_bytes(<<-1::size(size)>>)}
  end
  def normalize(%{validators: validators, mask_active: mask} = set) do
    :ok = BLS12AggSig.validate_mask(mask, length(validators))
    set
  end

  def roster(%{validators: validators}), do: validators

  def active(%{validators: validators, mask_active: mask}) do
    BLS12AggSig.unmask_trainers(validators, mask, length(validators))
  end

  def active_count(%{mask_active: mask}), do: Util.popcnt(mask)
end
