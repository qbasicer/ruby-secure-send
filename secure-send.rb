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

dest = args["--dest"]

if (dest == nil || dest.class != String) then
	raise "Requires a '--dest' argument, exactly once, #{dest}"
end

if (dest.include?(",")) then
	dest = dest.split(",")
	dest.map!{|value|
		value.chomp
	}
end

file = args.extra

if (file.empty? || file.length > 1) then
	raise "You can only specify one file"
end

se = SecureEngine.new({})

se.secure_send(dest, file.first)

