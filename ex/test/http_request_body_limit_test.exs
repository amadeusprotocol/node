defmodule Ama.MultiServerBodyLimitTest do
  use ExUnit.Case, async: true

  defp request(content_length) do
    headers = if is_nil(content_length), do: %{}, else: %{"content-length" => content_length}
    %{headers: headers}
  end

  test "accepts a body at the endpoint's configured limit" do
    limit = 1024 * 1024

    assert Ama.MultiServer.validate_body_length(request(Integer.to_string(limit)), limit) == :ok
  end

  test "rejects a body above the endpoint's configured limit" do
    limit = 1024 * 1024

    assert Ama.MultiServer.validate_body_length(request(Integer.to_string(limit + 1)), limit) ==
             {:error, :payload_too_large}
  end

  test "rejects missing and malformed content lengths" do
    limit = 1024 * 1024

    assert Ama.MultiServer.validate_body_length(request(nil), limit) == {:error, :length_required}

    assert Ama.MultiServer.validate_body_length(request("not-a-number"), limit) ==
             {:error, :invalid_content_length}

    assert Ama.MultiServer.validate_body_length(request("-1"), limit) ==
             {:error, :invalid_content_length}
  end
end
