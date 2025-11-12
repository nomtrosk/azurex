defmodule Azurex.Authorization.ManagedIdentityTest do
  use ExUnit.Case
  doctest Azurex.Authorization.ManagedIdentity

  alias Azurex.Authorization.ManagedIdentity

  import Azurex.ManagedIdentityHelpers
  import ExUnit.CaptureLog

  @expected_access_token Base.encode64("token")

  setup do
    bypass = Bypass.open()

    Application.put_env(:azurex, Azurex.Blob.Config, auth_url: "http://localhost:#{bypass.port}")

    {:ok, bypass: bypass}
  end

  defp generate_request do
    %HTTPoison.Request{
      method: :put,
      url: "https://example.com/sample-path",
      body: "sample body",
      headers: [
        {"x-ms-blob-type", "BlockBlob"}
      ],
      options: [recv_timeout: :infinity]
    }
  end

  defp prepare_auth_endpoint(bypass, token_expires_in) do
    Bypass.expect_once(bypass, "POST", "/tenant_id/oauth2/v2.0/token", fn conn ->
      token_response =
        %{access_token: @expected_access_token, expires_in: token_expires_in} |> Jason.encode!()

      Plug.Conn.resp(conn, 200, token_response)
    end)
  end

  describe "add_bearer_token/4" do
    test "Test bearer cache", %{bypass: bypass} do
      federated_token_file_path = create_token_file()
      # # Set token time so it expires in 100 seconds
      token_expires_in = :timer.seconds(5)
      # # Expect one token request because the second will be cached
      prepare_auth_endpoint(bypass, token_expires_in)

      input_request = generate_request()

      for _ <- 1..2 do
        output_request =
          ManagedIdentity.add_bearer_token(
            input_request,
            "client_id",
            "tenant_id",
            federated_token_file_path
          )

        assert output_request == %HTTPoison.Request{
                 body: "sample body",
                 headers: [
                   {"Authorization", "Bearer #{@expected_access_token}"},
                   {"x-ms-blob-type", "BlockBlob"}
                 ],
                 method: :put,
                 options: [recv_timeout: :infinity],
                 params: %{},
                 url: "https://example.com/sample-path"
               }
      end
    end

    test "Test bearer cache refresh", %{bypass: bypass} do
      federated_token_file_path = create_token_file()

      # Set token time so it expired 100 seconds ago
      token_expires_in = -100
      input_request = generate_request()

      for _ <- 1..2 do
        # Now we expect two token requests because the token is expired
        prepare_auth_endpoint(bypass, token_expires_in)

        output_request =
          ManagedIdentity.add_bearer_token(
            input_request,
            "client_id",
            "tenant_id",
            federated_token_file_path
          )

        assert output_request == %HTTPoison.Request{
                 body: "sample body",
                 headers: [
                   {"Authorization", "Bearer #{@expected_access_token}"},
                   {"x-ms-blob-type", "BlockBlob"}
                 ],
                 method: :put,
                 options: [recv_timeout: :infinity],
                 params: %{},
                 url: "https://example.com/sample-path"
               }
      end
    end

    test "bearer cache works across processes", %{bypass: bypass} do
      federated_token_file_path = create_token_file()

      # Set token time so it expires in 100 seconds
      token_expires_in = :timer.seconds(-100)
      input_request = generate_request()

      # Expect one token request because the second will be cached
      prepare_auth_endpoint(bypass, token_expires_in)

      # Fetch bearer token and cache
      assert %HTTPoison.Request{} =
               ManagedIdentity.add_bearer_token(
                 input_request,
                 "client_id",
                 "tenant_id",
                 federated_token_file_path
               )

      task =
        Task.async(fn ->
          prepare_auth_endpoint(bypass, token_expires_in)

          ManagedIdentity.add_bearer_token(
            input_request,
            "client_id",
            "tenant_id",
            federated_token_file_path
          )
        end)

      assert Task.await(task) == %HTTPoison.Request{
               body: "sample body",
               headers: [
                 {"Authorization", "Bearer #{@expected_access_token}"},
                 {"x-ms-blob-type", "BlockBlob"}
               ],
               method: :put,
               options: [recv_timeout: :infinity],
               params: %{},
               url: "https://example.com/sample-path"
             }
    end

    test "Failure", %{bypass: bypass} do
      federated_token_file_path = create_token_file()

      Bypass.expect_once(bypass, "POST", "/tenant_id/oauth2/v2.0/token", fn conn ->
        Plug.Conn.resp(conn, 403, "Not authorized")
      end)

      input_request = generate_request()

      {output_request, log} =
        with_log(fn ->
          ManagedIdentity.add_bearer_token(
            input_request,
            "client_id",
            "tenant_id",
            federated_token_file_path
          )
        end)

      assert output_request == %HTTPoison.Request{
               body: "sample body",
               headers: [
                 {"Authorization", "Bearer No token"},
                 {"x-ms-blob-type", "BlockBlob"}
               ],
               method: :put,
               options: [recv_timeout: :infinity],
               params: %{},
               url: "https://example.com/sample-path"
             }

      assert log =~ "Failed to fetch bearer token. Reason: 403: Not authorize"
    end
  end
end
