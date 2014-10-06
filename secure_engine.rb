require 'openssl'
require 'base64'

unless Dir.respond_to?(:exists?)
  	class Dir
	    def self.exists?(path)
	      	return File.exists?(path)
	    end
  end
end


class SecureEngine
	def initialize

		#puts OpenSSL::Cipher.ciphers

		homedir = File.expand_path("~/")
		@self_config_file= "#{homedir}/.secure/config"

		self_config = File.new(@self_config_file).read

		@private_key = nil
		@public_key_file = nil
		@node_name = nil
		@inbox = nil
		@sync_dir = nil
		@tmpdir = "#{homedir}/.secure/tmp"

		lines = self_config.lines{|line|
			if (line.include?("=")) then
				idx = line.index "="
				var = line[0..idx-1].chomp
				val = line[idx+1..-1].chomp
				if (var == "name") then
					@node_name = val
				elsif (var == "pub_key") then
					@public_key_file = val
				elsif (var == "pri_key") then
					@private_key = OpenSSL::PKey::RSA.new(File.read(val))
				elsif (var == "sync_dir") then
					@sync_dir = val
				elsif (var == "inbox") then
					@inbox = val
				elsif (var == "tmpdir") then
					@tmpdir = val
				end
			end
		}
		if (@private_key == nil) then
			raise "Private key not specified or invalid"
		elsif (@public_key_file == nil) then
			raise "Public key file not specified or invalid"
		elsif (@node_name == "NODE_NAME_HERE") then
			raise "Invalid node name"
		elsif (@inbox == nil) then
			raise "Invalid inbox"
		elsif (@sync_dir == nil) then
			raise "Invalid sync_dir"
		end
		if (!Dir.exists?(@tmpdir)) then
			Dir.mkdir @tmpdir
		end

		should_write = false
		sync_key_loc = "#{@sync_dir}/#{@node_name}.pub"
		if (!File.exists? sync_key_loc) then
			should_write = true
		else
			if (File.new(@public_key_file).read != File.new(sync_key_loc).read) then
				should_write = true
			end
		end

		if (should_write) then
			f = File.open(sync_key_loc, "w")
			puts "Writing public-key to #{@sync_dir}/#{@node_name}.pub"
			f.write File.new(@public_key_file).read
			f.close
		end
	end

	def secure_send(dest, file)
		unique = Digest::SHA1.hexdigest "#{file}#{Time.now}#{rand}"
		puts "Sending #{file} to #{dest}"
		start = Time.now
		dest = dest.downcase
		remote_public_key = "#{@sync_dir}/#{dest}.pub"
		if (!File.exists?(remote_public_key)) then
			raise "Remote #{dest} doesn't have a key at #{remote_public_key}"
		end
		pubkey = OpenSSL::PKey::RSA.new(File.read(remote_public_key))
		
		cipher = OpenSSL::Cipher::AES256.new(:CBC)
		cipher.encrypt
		key = Base64.encode64(cipher.random_key).chomp
		iv = Base64.encode64(cipher.random_iv).chomp

		file_contents = File.new(file).read

		sha1 = Digest::SHA1.hexdigest file_contents

		file_contents = cipher.update(file_contents) + cipher.final
		base_name = File.basename(file)
		xfer_name = "#{unique}.sft"
		f = File.open("#{@sync_dir}/#{xfer_name}", "w")
		f.write file_contents
		f.close

		# Clear encrypted data from memory
		file_contents = nil
		
		xfer_file_contents = "key=#{key}\niv=#{iv}\nname=#{base_name}\nfile=#{xfer_name}\nsha1=#{sha1}"

		xfer_file_contents = pubkey.public_encrypt(xfer_file_contents)
		f = File.open("#{@sync_dir}/#{dest}-#{unique}.smf", "w")
		
		f.write xfer_file_contents
		f.close
		start = Time.now - start
		puts "MD: #{dest}-#{unique}.smf, XFER: #{xfer_name}, Elapsed: #{start}"
	end

	def rx_server
		t = Thread.new{
			loop do
				entries = Dir.entries(@sync_dir)

				entries.each{|entry|
					if (entry.start_with?(@node_name) && entry.end_with?(".smf")) then
						if (Time.now - File.mtime("#{@sync_dir}/#{entry}") > 15) then
							puts "TDIFF: #{Time.now - File.mtime("#{@sync_dir}/#{entry}")}"
							start = Time.now
							unique = Digest::SHA1.hexdigest "#{entry}#{Time.now}"
														

							xfer_file_contents = File.new("#{@sync_dir}/#{entry}").read
							xfer_file_contents = @private_key.private_decrypt(xfer_file_contents)

							key = nil
							iv = nil
							name = nil
							file = nil
							tsha1 = nil
							sha1 = nil
							xfer_file_contents.split("\n").each{|line|
								if (line.include?("=")) then
									idx = line.index("=")
									var = line[0..idx-1].chomp
									val = line[idx+1..-1].chomp
									if (var == "key") then
										key = Base64.decode64 val
									elsif (var == "iv") then
										iv = Base64.decode64 val
									elsif (var == "name") then
										name = val
									elsif (var == "file") then
										file = val
									elsif (var == "sha1") then
										tsha1 = val
									end
								end
							}

							raise "Missing key" if key.nil?
							raise "Missing iv" if iv.nil?
							raise "Missing name" if name.nil?
							raise "Missing file" if file.nil?

							if (File.exists?("#{@sync_dir}/#{file}") && (Time.now - File.mtime("#{@sync_dir}/#{file}")) > 15) then
								puts "Receiving file #{@inbox}/#{name}"

								File.rename("#{@sync_dir}/#{entry}", "#{@tmpdir}/#{unique}.smf")
								file_contents = File.new("#{@sync_dir}/#{file}").read
								cipher = OpenSSL::Cipher::AES256.new(:CBC)
								cipher.decrypt
								cipher.key = key
								cipher.iv = iv
								file_contents = cipher.update(file_contents) + cipher.final
								if (tsha1 != nil) then
									sha1 = Digest::SHA1.hexdigest file_contents
									if (tsha1 != sha1) then
										puts "Calculated sha1 #{sha1} does not match expected sha1 #{tsha1}"
									end
								end

								f = File.open("#{@inbox}/#{name}", "w")
								f.write file_contents
								f.close

								File.delete "#{@sync_dir}/#{file}"
								File.delete "#{@tmpdir}/#{unique}.smf"
								start = Time.now - start
								if (sha1) then
									puts "Received file #{@inbox}/#{name} - #{sha1} @ #{Time.now} - #{start}s"
								else
									puts "Received file #{@inbox}/#{name} @ #{Time.now} - #{start}s"
								end
							end
						else
							puts "Waiting for metadata to cool off first.  TDIFF: #{Time.now - File.mtime("#{@sync_dir}/#{entry}")}"
						end
					end
				}

				sleep(5)
			end
		}

		t.join
	end

	def self.ensure_keys
		homedir = File.expand_path("~/")

		self_config = "#{homedir}/.secure/config"

		if (!File.exists?(self_config)) then
			if (!Dir.exists?("#{homedir}/.secure")) then
				Dir.mkdir "#{homedir}/.secure"
			end

			f = File.open(self_config, "w")
			f.puts "name=NODE_NAME_HERE"
			f.puts "pub_key=#{homedir}/.secure/self.pub"
			f.puts "pri_key=#{homedir}/.secure/self.key"
			f.puts "sync_dir=#{homedir}/global/secure"
			f.puts "inbox=#{homedir}/inbox"
			f.close

			puts "Generating keys"
			sys1_pri = OpenSSL::PKey::RSA.generate( 4096 )
			sys1_pub = sys1_pri.public_key

			f = File.open("#{homedir}/.secure/self.pub", "w")
			f.write sys1_pub
			f.close

			f = File.open("#{homedir}/.secure/self.key", "w")
			f.write sys1_pri
			f.close

			raise "No configuration present, please modify #{self_config}"
		end

		self_config = File.new(self_config).read
		self_config = self_config.split("\n")
		has_valid_name = false
		has_valid_pub_key = false
		has_valid_pri_key = false
		has_valid_sync_dir = false
		has_valid_inbox = false
		self_config.each{|line|
			if (line.include? "=") then
				idx = line.index "="
				var = line[0..idx-1].chomp
				val = line[idx+1..-1].chomp
				if (var == "name" && val != "NODE_NAME_HERE") then
					has_valid_name = true
				elsif (var == "pub_key" && File.exists?(val)) then
					has_valid_pub_key = true
				elsif (var == "pri_key" && File.exists?(val)) then
					has_valid_pri_key = true
				elsif (var == "sync_dir" && Dir.exists?(val)) then
					has_valid_sync_dir = true
				elsif (var == "inbox" && Dir.exists?(val)) then
					has_valid_inbox = true
				end
			else
				puts line
			end
		}
		if (!has_valid_name) then
			raise "Node name hasn't been properly configured, please modify #{homedir}/.secure/config"
		elsif (!has_valid_pri_key) then
			raise "No valid private key specified in #{homedir}/.secure/config"
		elsif (!has_valid_pub_key) then
			raise "No valid public key specified in #{homedir}/.secure/config"
		elsif (!has_valid_sync_dir) then
			raise "No valid sync_dir specified in #{homedir}/.secure/config"
		elsif (!has_valid_inbox) then
			raise "No valid inbox specified in #{homedir}/.secure/config"
		end
	end
end

SecureEngine.ensure_keys