unless Kernel.respond_to?(:require_relative)
  module Kernel
    def require_relative(path)
      require File.join(File.dirname(caller[0]), path.to_str)
    end
  end
end

require_relative 'secure_engine.rb'

class CmdArgs
	def initialize
		currArg = nil
		extras = []
		hash = {}
		ARGV.each{|arg|
			if (arg.start_with?("--")) then
				currArg = arg
			elsif (arg.start_with?("-")) then
				currArg = nil
				if (hash[arg] == nil) then
					hash[arg] = []
				end
				hash[arg].push(true)
			else
				if (currArg != nil) then
					if (hash[currArg] == nil) then
						hash[currArg] = []
					end
					hash[currArg].push(arg)
					currArg = nil
				else
					extras.push arg
				end
			end
		}
		@extras = extras
		@hash = hash
	end

	def [](key)
		larray = @hash[key]
		if (larray.nil?) then
			return nil
		end
		if (larray.length == 1) then
			return larray.first
		end
		larray
	end

	def extra
		@extras
	end
end

args = CmdArgs.new

se = SecureEngine.new({})
input_file = nil
output_file = nil
pubkey = nil

if (args["--input"]) then
	input_file = File.new(args["--input"], "r")
else
	input_file = $stdin
end

if (args["--output"]) then
	output_file = File.new(args["--output"], "w")
else
	output_file = $stdout
end

if (args["--pubkey"]) then
	OpenSSL::PKey::RSA.new(File.read(args["--pubkey"]))
end

okay = true

begin
	se.receive_secure_package(pubkey, input_file, output_file)
rescue Exception=>e
	puts "Receive failed: #{e.inspect}"
	puts e.backtrace.join("\n\t")
	okay = false
end

input_file.close
output_file.close

if (args["--output"]) then
	File.delete(args["--output"]) unless okay
end

