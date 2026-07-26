defmodule AutoUpdateReleaseVerify do
  @moduledoc """
  Verifies auto-update release artifacts against Ed25519 public keys that are
  PINNED (compiled into this binary). This is the real gate for auto-update —
  TLS only proves who we talked to; this proves the author signed the bytes.

  Signatures are SSHSIG blobs from `ssh-keygen -Y sign`, so a release can be
  signed with an ordinary offline SSH ed25519 key (e.g. the maintainer's GitHub
  commit-signing key) with no extra tooling. `ex/sign_release.sh` signs the
  "<version> <sha256>" manifest line and bundles it with the signature into the
  single `amadeusd.sig` release asset (manifest line, then the armored SSHSIG).

  The pubkey MUST be pinned here, never fetched at runtime — a key from the
  network would let whoever controls that channel defeat the whole scheme.
  """

  #raw 32-byte ed25519 public keys accepted for a release.
  @pubkeys [
    <<230, 11, 80, 254, 200, 124, 253, 110, 145, 12, 71, 199, 51, 97, 214, 135,
      72, 103, 217, 216, 203, 198, 196, 234, 60, 203, 24, 36, 184, 30, 10, 223>>,
  ]

  @namespace "amadeus-release"

  def pinned_pubkeys(), do: @pubkeys
  def namespace(), do: @namespace

  @doc """
  Verify an armored SSHSIG over `message`. Returns `:ok` only if a pinned key
  signed exactly these bytes under our namespace; any error otherwise.
  """
  def verify(message, sshsig_armored) when is_binary(message) and is_binary(sshsig_armored) do
    try do
      blob = dearmor(sshsig_armored)
      <<"SSHSIG", 1::32, rest::binary>> = blob
      {pubkey_blob, rest} = ssh_string(rest)
      {namespace, rest} = ssh_string(rest)
      {_reserved, rest} = ssh_string(rest)
      {hash_algo, rest} = ssh_string(rest)
      {sig_blob, _rest} = ssh_string(rest)

      raw_pk = ed25519_raw_from_blob(pubkey_blob)
      raw_sig = ed25519_raw_from_blob(sig_blob)

      cond do
        namespace != @namespace -> {:error, :bad_namespace}
        raw_pk not in @pubkeys -> {:error, :unpinned_key}
        true ->
          #ed25519 signs the SSHSIG-framed digest of the message, not the message
          h = digest(hash_algo, message)
          signed = "SSHSIG" <> sshstr(namespace) <> sshstr("") <> sshstr(hash_algo) <> sshstr(h)
          if :crypto.verify(:eddsa, :none, signed, raw_sig, [raw_pk, :ed25519]) do
            :ok
          else
            {:error, :bad_signature}
          end
      end
    rescue
      _ -> {:error, :malformed}
    catch
      _, _ -> {:error, :malformed}
    end
  end

  defp dearmor(text) do
    text
    |> String.split("\n")
    |> Enum.reject(&(&1 == "" or String.starts_with?(&1, "-----")))
    |> Enum.join("")
    |> Base.decode64!()
  end

  defp ssh_string(<<len::32, val::binary-size(len), rest::binary>>), do: {val, rest}
  defp sshstr(bin), do: <<byte_size(bin)::32, bin::binary>>

  #a ssh-ed25519 blob is: string "ssh-ed25519", string raw(32 for pk, 64 for sig)
  defp ed25519_raw_from_blob(blob) do
    {"ssh-ed25519", rest} = ssh_string(blob)
    {raw, _} = ssh_string(rest)
    raw
  end

  defp digest("sha512", m), do: :crypto.hash(:sha512, m)
  defp digest("sha256", m), do: :crypto.hash(:sha256, m)
end
