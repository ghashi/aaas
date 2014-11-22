require_relative '../certificate_wrapper/certificate_wrapper'

namespace :app do
  desc "This task erases the database and creates new pair of keys"
  task :restart do
    Rake::Task['db:reset'].invoke
    p "Users detroyed!"

    keys = CertificateWrapper.ecdsa_keygen()
    out_file = File.new("config/keys", "w")
    out_file.puts(keys[0])
    out_file.puts(keys[1])
    out_file.close
    p "New pair of keys generated!"
  end
end
