require 'rails_helper'

RSpec.describe Api::V1::UsersController, :type => :controller do
  describe "POST #login" do
    context "when user is present in the list of current users" do
      let(:user) {FactoryGirl.create(:user)}
      let(:session_key){
        {session_key: "session_key"}
      }

      it "should return get request response" do
        allow(CryptoWrapper).to receive(:verify).and_return(true)
        post :login, id: user.id, token: {key: "1x1", timestamp: "11", count: "12", index: "13" }, sig: "sig" , supplicant: "sup"
        expect(response.body).to eq session_key.to_json
      end

      it "but verify returns false, then it should return bad request response" do
        allow(CryptoWrapper).to receive(:verify).and_return(false)
        post :login, id: user.id, token: {key: "1x1", timestamp: "11", count: "12", index: "13" }, sig: "sig" , supplicant: "sup"
        expect(response.status).to eq 400
      end

      it "but user count is lower than 12, then it should return bad request response" do
        fake_user = FactoryGirl.create(:user, token_count: 12)
        post :login, id: fake_user.id, token: {key: "1x1", timestamp: "11", count: "11", index: "13" }, sig: "sig" , supplicant: "sup"
        expect(response.status).to eq 400
      end

      it "but user count is higher than 1024, then it should return bad request response" do
        fake_user = FactoryGirl.create(:user, token_count: 1025)
        post :login, id: fake_user.id, token: {key: "1x1", timestamp: "11", count: "1025", index: "13" }, sig: "sig" , supplicant: "sup"
        expect(response.status).to eq 400
      end
    end

    context "when user is not present in the list of current users" do
      it "should return bad request response" do
        post :login, token: {key: "1x1", timestamp: "11", count: "12", index: "13" }, sig: "sig" , supplicant: "sup"
        expect(response.status).to eq 400
      end
    end
  end

  describe "POST #register" do
    let(:user) {FactoryGirl.create(:user)}
    let(:certificate){
      {certificate: "MTcwMTM3MDA3MSBURVNURSBkbyBDRVJUSUZJQ0FURQAyMDE0MTEyMjE0NDUwMAAyMDE1MTEzMDIyNTc1MQCc0j3+fURQ/VNY0L3U51MD8Wxb/fEsk8pn60F+u1BWWCOTVqDXpp0q/m7o01U71kaoMUOZXtdjxcKkQ331mdUYhgmOJcOnjrlE5dhVmn7PKAvtTM04OP5ELxd9iYJBy09xOvznlLkf+JvcXeAEcY2QKHxmDRgFiHg="}
    }

    it "if HMAC is ok, should return the certificate" do
      post :register, id: user.id, csr: "MTcwMTM3MDA3MSBURVNURSBkbyBDRVJUSUZJQ0FURQAyMDE0MTEyMjE0NDUwMACc0j3+fURQ/VNY0L3U51MD8Wxb/fEsk8pn60F+u1BWWCOTVqDXpp0q/m7o01U71kaoMUOZXtdjxcKkQ331mdUYhgmOJcOnjrlE5dhVmn7PKAAAANemO47F3zH9MG9xK5x7D7MAAQB2X9uTwfcTIQGbesavpd2BAQEA8Dhx/mG/2KtZPNgJGjpR9QIBAAJfT8mquNS4PrinrwJQw3UDAQDK8agS1vM48Z9kS2zeT44BBAEAri/Kz43YdglEecrzngMitgUBALJGIv6v90uU10uABKkAVGcGAQDCsuR+Oeafhb/rWMCLHubzBwEAb2U65YOmJIwxNA8byH2PpQgBALZZRN3Db8yNDXJ82SeoOEMJAQDm/SWG/wqObEj+S//LfEYqerRTxxyeKfrE5ZKJvhTlwsYqT7nIbX+7im72D/uD5j06fJ4pguX1l5M0wU/KeQya1Lca/DP7USQfeb+O2WLxiLxHEZdFUSctTGgGT9K+tUoFEx+AhnPsxDYYZpgmsLXz8yJ6pRxaHvZ9LlIi/aBi2KbTqOLCpBVTEjKzvHIOC3bgZwNBIUFi/UACqQkn9v2BEn5kO+4WyP3C7OYfhQtL57Q9yje64ImbTLOe6VwsHVGXTK3lwP7Qmtms0gGGOh4ifbCBGepqLTDX6XY5426mPnhyIzlEUWJUZD0kqgDzLdl0hMOgb8UpoaH72Qmn5clBsdJKJYynGbsiSBl8Vb/JbZ1qd5VeSYMeL/IRPcXntsozZz9CUl2FoogxXF0KcRhEkj0neDGbAYF5TDUAQNOyQfSZtvxBe1NwAOXkBGefPLMetVYlsK+IJAoRcUojLYYHpYHgAhom7KWMvRKjX1RwDKXXlvcKtqZt7UC4/abasJMzp3g6ANKlEvUDa8WZ2MTPnd8LM1W9c3GM/vZw4N8Zu20c1NK4ZIr+mqKstqCaJiAhRAqzox8JLlIkJaeGCWNkVvOkT6KqoWbdX+7cSfKt80BAgVocdWvTmGSYN2Q24Bqx7LJFYlgnAc1w3Y3i8xBwIFEJBb6k/wWuOWbxu89x+HbzYuFBXCx5CRcK4UdT4EN3A5KGAXYPqt4K9mIjmu8ru9kP/VwrWnanMYTAVpNqHq/vs9VEbb8V5IwiKJrL0O7wz6UACxZxSEg6BRbMaRIZckKuLG90NCMl04skarDai3hqfY3zgh3oh0BL94x18L85H7p30/DWg8GdH9kiIXKvK6TLJcAC0ZKFGpU17kgfjlkUT/Je81hodHn0K2b/a2Vsu74OVusMdFHcyZEYXtyDCCjJIjVO5Fx6Xo3A+YxG+sBqUddxQ6tSneIVKd+pXR8jlPowIH4blT4GRdQrYtfhZvcgRobmt3V7/2UDDsSN7ISfeW3QxUAyWRUc0M4NT4Gogdz6mOgr60Z5eKkJHNzVJS6q5tYj5f4frOHCmh4GJT2soEHtFON9w2I3qAGnqnEDurWqimg+6y7pHGSwhNVXq6IckQ6EI4QHg08DHW0rlQpnz9kJtZ2z11m7t8VcYS1fjFLV+QBsi03T05WhUH2rXpMpGBNo6hfXZXydL0UHeCGskadlMncOcuO9niAugYTVMWUu+JY8jv/A0xoAO+PyXeTD6ZXv2fwBVjOk4/is1VB/fG3kD7Fo0TufMUDqNMIzjv5FL04r2wiyHttf6JX8t5yJbsV9jK1uBolU/KkOjjM27np17dE+yzsJ1JHZS/vra+flz6e3O7Gn8FgUjwfOeChAKf1tnt/Ya+KlVDuln0UCQi6KqGNLw5CreR+Qn733R8LPbCFCdbuu5Up4U+GcqxW4Y4L7OkX+FBP6393s7sxtXpCywg6Ph442gXm7hXo=" , tag: "tag"
      expect(response.body).not_to eq "{\"certificate\":\"\"}"
    end

    it "if HMAC isnt ok, should return the bad request response" do
      pending "verify hmac should be implemented"
      post :register, id: user.id, csr: "csr" , tag: "tag"
      expect(response.status).to eq 400
    end

    it "if user isnt found, should return the bad request response" do
      post :register,csr: "csr" , tag: "tag"
      expect(response.status).to eq 400
    end
  end
end
