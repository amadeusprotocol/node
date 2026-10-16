defmodule ValidatorSet do
  @moduledoc """
  Bitmap indices use the immutable epoch roster; scheduling uses active keys.
  Pre-fork contexts remain lists. Post-fork contexts carry a canonical, MSB-first
  active mask, including when the activation record is still a legacy list.
  """

  def at_height(record, height) do
    if height < RDBProtocol.forkheight(), do: record, else: normalize(record)
  end

  def normalize(validators) when is_list(validators) do
    size = length(validators)
    %{validators: validators, mask_active: Util.pad_bitstring_to_bytes(<<-1::size(size)>>)}
  end
  def normalize(%{validators: validators, mask_active: mask} = set) do
    :ok = BLS12AggSig.validate_mask(mask, length(validators))
    set
  end

  def roster(validators) when is_list(validators), do: validators
  def roster(%{validators: validators}), do: validators

  def active(validators) when is_list(validators), do: validators
  def active(%{validators: validators, mask_active: mask}) do
    BLS12AggSig.unmask_trainers(validators, mask, length(validators))
  end

  def active_count(validators) when is_list(validators), do: length(validators)
  def active_count(%{mask_active: mask}), do: Util.popcnt(mask)
end
