module NSCA
	module PerformanceData
		class TimeUnitExpected < Exception
		end

		class Base
			extend Timeout
			extend Benchmark

			class <<self
				attr_reader :label, :unit, :warn, :crit, :min, :max
				def init *args
					a, o = args, args.last.is_a?( Hash) ? args.pop : {}
					@label, @unit = a[0]||o[:label], a[1]||o[:unit]
					@warn, @crit = a[2]||o[:warn], a[3]||o[:crit]
					@min, @max = a[4]||o[:min], a[5]||o[:max]
					raise ArgumentError, "Label expected"  unless @label
					@label = @label.to_s
					self
				end

				def measure &block
					f = case unit.to_s.to_sym
						when :s then 1
						when :ms then 1000
						else raise TimeUnitExpected, "Unit must be seconds (s) or miliseconds (ms) not (#{unit})"
						end
					exception = ::Class.new Timeout::Error
					timeout = max
					m = realtime do
						begin
							timeout timeout, exception, &block
						rescue exception
						end
					end
					new f * m
				end

				def to_sym() label.to_sym end
				def to_h() {label: @label, unit: @unit, warn: @warn, crit: @crit, min: @min, max: @max } end
				def to_a() [label, unit, warn, crit, min, max] end
				def clone( opts = nil) ::Class.new( self).init opts ? to_h.merge( opts) : to_h end
			end

			attr_reader :value
			def initialize( value) @value = value end
			def label()  self.class.label  end
			def unit()  self.class.unit  end
			def warn()  self.class.warn  end
			def crit()  self.class.crit  end
			def min()  self.class.min  end
			def max()  self.class.max  end
			def to_a() [label, value, unit, warn, crit, min, max] end
			def to_s() "'#{label.gsub /[\n'\|]/, ''}'=#{value}#{unit},#{warn},#{crit},#{min},#{max}" end
			def to_sym() self.class.to_sym end

			def to_h
				{label: @label, value: @value, unit: @unit, warn: @warn, crit: @crit, min: @min, max: @max}
			end

			def return_code
				if @value.nil? then 3
				elsif crit <= @value then 2
				elsif warn <= @value then 1
				else 0
				end
			end
		end

		class <<self
			def new( *args) ::Class.new( Base).init *args end
			def create label, *args
				cl = new label, *args
				clname = NSCA::Helper.class_name_gen label
				self.const_set clname, cl  if clname
				cl
			end
		end
	end

	module Check
		class Base
			attr_accessor :return_code, :status, :timestamp
			attr_reader :perfdatas

			def initialize return_code = nil, status = nil, perfdatas = nil, timestamp = nil
				@perfdatas = {}
				init return_code, status, perfdatas, timestamp || Time.now
			end

			def init return_code = nil, status = nil, perfdatas = nil, timestamp = nil
				@return_code = return_code  if return_code
				@status = status  if status
				case perfdatas
				when Hash
					perfdatas.each &method( :[])
				when Array
					push *perfdatas
				end
				@timestamp = timestamp  if timestamp
				self
			end

			def [] perfdata_label
				pd = @perfdatas[perfdata_label.to_sym]
				pd && pd.value
			end

			def push *perfdatas
				perfdatas.each {|perfdata| @perfdatas[perfdata.label.to_sym] = perfdata }
				@perfdatas
			end

			def perfdata_for label
				if label.is_a? PerformanceData::Base
					label
				else
					label = label.to_sym
					self.class.perfdatas[label] || PerformanceData::Base.new( label)
				end
			end

			def []= perfdata_label, value
				return push value  if value.is_a? PerformanceData::Base
				perfdata_label = perfdata_label.to_sym
				@perfdatas[perfdata_label] = perfdata_for( perfdata_label).new value
			end

			def text
				r = "#{status || ReturnCode.find(retcode)}"
				r += " | #{perfdatas.each_value.map( &:to_s).join ' '}"  unless perfdatas.empty?
				r
			end

			def measure perfdata_label, &block
				push perfdata_for( perfdata_label).measure( &block)
			end
			def send() NSCA::send self end

			def ok( *args) init ReturnCode::OK, *args end
			def warning( *args) init ReturnCode::WARNING, *args end
			alias warn warning
			def critical( *args) init ReturnCode::CRITICAL, *args end
			alias crit critical
			def unknown( *args) init ReturnCode::UNKNOWN, *args end

			def determine_return_code
				self.class.perfdatas.map do |label, pdc|
					pd = @perfdatas[label]
					pd ? pd.return_code : -1
				end.max
			end

			def retcode
				rc = return_code || determine_return_code
				(0..3).include?(rc) ? rc : 3
			end

			def service() self.class.service end
			def hostname() self.class.hostname end
			def to_a() [timestamp, retcode, hostname, service, text] end
			def to_h
				{timestamp: timestamp, return_code: retcode, hostname: hostname, server: service, status: text}
			end

			def to_packet version = nil
				version ||= PacketV3
				version.new timestamp, retcode, hostname, service, text
			end

			class <<self
				attr_reader :service, :hostname, :perfdatas
				def init *args
					a, o = args, args.last.is_a?( Hash) ? args.pop : {}
					service, hostname = nil, perfdatas = nil
					@service, @hostname, @perfdatas = a[0]||o[:service], a[1]||o[:hostname]||`hostname`.chomp, {}
					perfdatas = a[2]||o[:perfdatas]
					perfdatas.each {|pd| @perfdatas[pd.to_sym] = pd }  if perfdatas
					self
				end

				def ok( status = nil, perfdatas = nil) new.ok status, perfdatas end
				def warning( status = nil, perfdatas = nil) new.warning status, perfdatas end
				alias warn warning
				def critical( status = nil, perfdatas = nil) new.warning status, perfdatas end
				alias crit critical
				def unknown( status = nil, perfdatas = nil) new.unknown status, perfdatas end

				def to_a() [service, hostname, perfdatas.dup] end
				def to_h() {service: service, hostname: hostname, perfdatas: perfdatas.values} end
				def to_sym() "#{hostname}|#{service}".to_sym end
				def clone( opts = nil) ::Class.new( self).init opts ? to_h.merge( opts) : to_h end
			end
		end

		class <<self
			def new service, hostname = nil, perfdatas = nil
				cl = Class.new Base
				cl.init service, hostname, perfdatas
				cl
			end

			def create service, hostname = nil, perfdatas = nil
				cl = new service, hostname, perfdatas
				clname = NSCA::Helper.class_name_gen service.to_s
				self.const_set clname, cl  if clname
				cl
			end
		end
	end

	module Checks
		def perfdata( *params) NSCA::PerformanceData.new( *params) end

		def check service, hostname, perfdatas = nil
			perfdatas ||= []
			perfdatas.map! {|cl| cl.is_a?( Symbol) ? const_get( cl) : cl }
			NSCA::Check.new service, hostname, perfdatas
		end
	end
end
