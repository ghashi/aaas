require 'rails_helper'
require_relative '../../../lib/certificate_wrapper'
require_relative '../../../lib/certificate_wrapper/certificate_wrapper'
require_relative '../../../lib/services/get_keys'

describe CertificateWrapper do
  context "#generate_certificate" do
    it "generates a certificate for a good csr" do
      csr = "MTcwMTM3MDA3MSBURVNURSBkbyBDRVJUSUZJQ0FURQAyMDE0MTEyMjE0NDUwMACc0j3+fURQ/VNY0L3U51MD8Wxb/fEsk8pn60F+u1BWWCOTVqDXpp0q/m7o01U71kaoMUOZXtdjxcKkQ331mdUYhgmOJcOnjrlE5dhVmn7PKAAAANemO47F3zH9MG9xK5x7D7MAAQB2X9uTwfcTIQGbesavpd2BAQEA8Dhx/mG/2KtZPNgJGjpR9QIBAAJfT8mquNS4PrinrwJQw3UDAQDK8agS1vM48Z9kS2zeT44BBAEAri/Kz43YdglEecrzngMitgUBALJGIv6v90uU10uABKkAVGcGAQDCsuR+Oeafhb/rWMCLHubzBwEAb2U65YOmJIwxNA8byH2PpQgBALZZRN3Db8yNDXJ82SeoOEMJAQDm/SWG/wqObEj+S//LfEYqerRTxxyeKfrE5ZKJvhTlwsYqT7nIbX+7im72D/uD5j06fJ4pguX1l5M0wU/KeQya1Lca/DP7USQfeb+O2WLxiLxHEZdFUSctTGgGT9K+tUoFEx+AhnPsxDYYZpgmsLXz8yJ6pRxaHvZ9LlIi/aBi2KbTqOLCpBVTEjKzvHIOC3bgZwNBIUFi/UACqQkn9v2BEn5kO+4WyP3C7OYfhQtL57Q9yje64ImbTLOe6VwsHVGXTK3lwP7Qmtms0gGGOh4ifbCBGepqLTDX6XY5426mPnhyIzlEUWJUZD0kqgDzLdl0hMOgb8UpoaH72Qmn5clBsdJKJYynGbsiSBl8Vb/JbZ1qd5VeSYMeL/IRPcXntsozZz9CUl2FoogxXF0KcRhEkj0neDGbAYF5TDUAQNOyQfSZtvxBe1NwAOXkBGefPLMetVYlsK+IJAoRcUojLYYHpYHgAhom7KWMvRKjX1RwDKXXlvcKtqZt7UC4/abasJMzp3g6ANKlEvUDa8WZ2MTPnd8LM1W9c3GM/vZw4N8Zu20c1NK4ZIr+mqKstqCaJiAhRAqzox8JLlIkJaeGCWNkVvOkT6KqoWbdX+7cSfKt80BAgVocdWvTmGSYN2Q24Bqx7LJFYlgnAc1w3Y3i8xBwIFEJBb6k/wWuOWbxu89x+HbzYuFBXCx5CRcK4UdT4EN3A5KGAXYPqt4K9mIjmu8ru9kP/VwrWnanMYTAVpNqHq/vs9VEbb8V5IwiKJrL0O7wz6UACxZxSEg6BRbMaRIZckKuLG90NCMl04skarDai3hqfY3zgh3oh0BL94x18L85H7p30/DWg8GdH9kiIXKvK6TLJcAC0ZKFGpU17kgfjlkUT/Je81hodHn0K2b/a2Vsu74OVusMdFHcyZEYXtyDCCjJIjVO5Fx6Xo3A+YxG+sBqUddxQ6tSneIVKd+pXR8jlPowIH4blT4GRdQrYtfhZvcgRobmt3V7/2UDDsSN7ISfeW3QxUAyWRUc0M4NT4Gogdz6mOgr60Z5eKkJHNzVJS6q5tYj5f4frOHCmh4GJT2soEHtFON9w2I3qAGnqnEDurWqimg+6y7pHGSwhNVXq6IckQ6EI4QHg08DHW0rlQpnz9kJtZ2z11m7t8VcYS1fjFLV+QBsi03T05WhUH2rXpMpGBNo6hfXZXydL0UHeCGskadlMncOcuO9niAugYTVMWUu+JY8jv/A0xoAO+PyXeTD6ZXv2fwBVjOk4/is1VB/fG3kD7Fo0TufMUDqNMIzjv5FL04r2wiyHttf6JX8t5yJbsV9jK1uBolU/KkOjjM27np17dE+yzsJ1JHZS/vra+flz6e3O7Gn8FgUjwfOeChAKf1tnt/Ya+KlVDuln0UCQi6KqGNLw5CreR+Qn733R8LPbCFCdbuu5Up4U+GcqxW4Y4L7OkX+FBP6393s7sxtXpCywg6Ph442gXm7hXo="
      expect( CertificateWrapper.generate_certificate(csr, CertificateWrapper.valid, CertificateWrapper.ca_skey).length).to be > 0
    end
    it "doesnt generate a certificate for a bad csr" do
      csr = "mTcwMTM3MDA3MSBURVNURSBkbyBDRVJUSUZJQ0FURQAyMDE0MTEyMjE0NDUwMACc0j3+fURQ/VNY0L3U51MD8Wxb/fEsk8pn60F+u1BWWCOTVqDXpp0q/m7o01U71kaoMUOZXtdjxcKkQ331mdUYhgmOJcOnjrlE5dhVmn7PKAAAANemO47F3zH9MG9xK5x7D7MAAQB2X9uTwfcTIQGbesavpd2BAQEA8Dhx/mG/2KtZPNgJGjpR9QIBAAJfT8mquNS4PrinrwJQw3UDAQDK8agS1vM48Z9kS2zeT44BBAEAri/Kz43YdglEecrzngMitgUBALJGIv6v90uU10uABKkAVGcGAQDCsuR+Oeafhb/rWMCLHubzBwEAb2U65YOmJIwxNA8byH2PpQgBALZZRN3Db8yNDXJ82SeoOEMJAQDm/SWG/wqObEj+S//LfEYqerRTxxyeKfrE5ZKJvhTlwsYqT7nIbX+7im72D/uD5j06fJ4pguX1l5M0wU/KeQya1Lca/DP7USQfeb+O2WLxiLxHEZdFUSctTGgGT9K+tUoFEx+AhnPsxDYYZpgmsLXz8yJ6pRxaHvZ9LlIi/aBi2KbTqOLCpBVTEjKzvHIOC3bgZwNBIUFi/UACqQkn9v2BEn5kO+4WyP3C7OYfhQtL57Q9yje64ImbTLOe6VwsHVGXTK3lwP7Qmtms0gGGOh4ifbCBGepqLTDX6XY5426mPnhyIzlEUWJUZD0kqgDzLdl0hMOgb8UpoaH72Qmn5clBsdJKJYynGbsiSBl8Vb/JbZ1qd5VeSYMeL/IRPcXntsozZz9CUl2FoogxXF0KcRhEkj0neDGbAYF5TDUAQNOyQfSZtvxBe1NwAOXkBGefPLMetVYlsK+IJAoRcUojLYYHpYHgAhom7KWMvRKjX1RwDKXXlvcKtqZt7UC4/abasJMzp3g6ANKlEvUDa8WZ2MTPnd8LM1W9c3GM/vZw4N8Zu20c1NK4ZIr+mqKstqCaJiAhRAqzox8JLlIkJaeGCWNkVvOkT6KqoWbdX+7cSfKt80BAgVocdWvTmGSYN2Q24Bqx7LJFYlgnAc1w3Y3i8xBwIFEJBb6k/wWuOWbxu89x+HbzYuFBXCx5CRcK4UdT4EN3A5KGAXYPqt4K9mIjmu8ru9kP/VwrWnanMYTAVpNqHq/vs9VEbb8V5IwiKJrL0O7wz6UACxZxSEg6BRbMaRIZckKuLG90NCMl04skarDai3hqfY3zgh3oh0BL94x18L85H7p30/DWg8GdH9kiIXKvK6TLJcAC0ZKFGpU17kgfjlkUT/Je81hodHn0K2b/a2Vsu74OVusMdFHcyZEYXtyDCCjJIjVO5Fx6Xo3A+YxG+sBqUddxQ6tSneIVKd+pXR8jlPowIH4blT4GRdQrYtfhZvcgRobmt3V7/2UDDsSN7ISfeW3QxUAyWRUc0M4NT4Gogdz6mOgr60Z5eKkJHNzVJS6q5tYj5f4frOHCmh4GJT2soEHtFON9w2I3qAGnqnEDurWqimg+6y7pHGSwhNVXq6IckQ6EI4QHg08DHW0rlQpnz9kJtZ2z11m7t8VcYS1fjFLV+QBsi03T05WhUH2rXpMpGBNo6hfXZXydL0UHeCGskadlMncOcuO9niAugYTVMWUu+JY8jv/A0xoAO+PyXeTD6ZXv2fwBVjOk4/is1VB/fG3kD7Fo0TufMUDqNMIzjv5FL04r2wiyHttf6JX8t5yJbsV9jK1uBolU/KkOjjM27np17dE+yzsJ1JHZS/vra+flz6e3O7Gn8FgUjwfOeChAKf1tnt/Ya+KlVDuln0UCQi6KqGNLw5CreR+Qn733R8LPbCFCdbuu5Up4U+GcqxW4Y4L7OkX+FBP6393s7sxtXpCywg6Ph442gXm7hXo="
      expect( CertificateWrapper.generate_certificate(csr, CertificateWrapper.valid, CertificateWrapper.ca_skey).length).to be > 0
    end
  end
  context "#ecdsa_keygen" do
    it "generates the pair of keys [skey, pkey]" do
      expect(CertificateWrapper.ecdsa_keygen().size).to eq 2
    end
  end
end
