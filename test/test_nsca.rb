require 'helper'
require 'dummy_server'
require 'securerandom'

class TestNSCA < Test::Unit::TestCase
	context 'xor' do
		should 'return a if a (random) will xored double with random key. (1000 rounds)' do
			1000.times do
				key_len = SecureRandom.random_number 1000
				a_len = SecureRandom.random_number 1000
				key = SecureRandom.random_bytes key_len
				a = SecureRandom.random_bytes a_len
				assert_equal a, NSCA.xor( key, NSCA.xor(key, a))
			end
		end
	end
end

class TestNSCACommunication < Test::Unit::TestCase
	Port = 5787
	def dummy_server *args
		server = Thread.new do
			begin
				NSCA.dummy_server *args
			rescue Object
				#STDERR.puts "#{$!.class}: #{$!}", $!.backtrace.map{|bt|"  #{bt}"}
			 	raise
		 	ensure
				#STDERR.puts "Dummy Server Shutdown"
			end
		end
		sleep 1 # server needs time to start...
		server
	end

	include NSCA::Checks

	context "our dummy test server on localhost:#{Port} with random password" do
		should 'receive data' do
			password = 'password' || SecureRandom.random_bytes
			timestamp = Time.now

			PD1 = perfdata :pd1_in_sec, :s, 10, 20, 0, 30
			PD2 = perfdata :pd2_in_1, 1, 0.99, 0.98, 0, 1
			PD3 = perfdata :pd3_count, :c, 3, 5, 0
			T0 = check 'TestNSCA0', 'localhost'
			T1 = check 'TestNSCA1', 'localhost', [PD1, PD2]
			T2 = check :TestNSCA2, 'localhost', [PD1, PD2, PD3]

			checks = []
			t0 = T0.new( 1, "0123456789"*51+"AB", nil, timestamp) # oversized service name
			checks << t0

			pd1 = PD1.new 3
			pd2 = PD2.new 0.9996
			pd3 = PD3.new 2
			t1 = T1.new( nil, "Should be OK", [pd1, pd2, pd3], timestamp)
			checks << t1

			NSCA::destinations.clear
			NSCA::destinations << NSCA::Client.new( 'localhost', Port, password)

			server = dummy_server port: Port, password: password
			NSCA::send *checks
			pc0, pc1 = server.value

			[[t0, pc0], [t1, pc1]].each do |(test, packet)|
				assert_equal test.hostname, packet.hostname
				assert_equal test.service, packet.service
				assert_equal timestamp.to_i, packet.timestamp.to_i
				assert_equal test.retcode, packet.return_code
			end
			# original with AB, but B is char 512 and will be replaced by \0
			assert_equal "0123456789"*51+"A", pc0.status
			assert_equal "Should be OK | 'pd1_in_sec'=3s,10,20,0,30 'pd2_in_1'=0.99961,0.99,0.98,0,1 'pd3_count'=2c,3,5,0,", pc1.status
		end

		should 'fail crc32 if wrong password' do
			password = 'password' || SecureRandom.random_bytes
			timestamp = Time.now
			T3 = check 'TestNSCA0', 'localhost'
			NSCA::destinations.clear
			NSCA::destinations << NSCA::Client.new( 'localhost', Port, password+'a')
			server = dummy_server hostname: 'localhost', port: Port, password: password
			NSCA::send [T3.new( 1, 'status', nil, timestamp)]
			assert_raise( NSCA::Packet::CSC32CheckFailed) { server.join }
		end
	end
end

class TestNSCA::ReturnCode < Test::Unit::TestCase
	context 'return code' do
		should( 'be 0 == OK') { assert NSCA::ReturnCode.find(0) == NSCA::ReturnCode::OK }
		should( 'be 1 == WARNING') { assert NSCA::ReturnCode.find(1) == NSCA::ReturnCode::WARNING }
		should( 'be 2 == CRITICAL') { assert NSCA::ReturnCode.find(2) == NSCA::ReturnCode::CRITICAL }
		should( 'be 3 == UNKNOWN') { assert NSCA::ReturnCode.find(3) == NSCA::ReturnCode::UNKNOWN }
	end
end

class TestNSCA::Helper < Test::Unit::TestCase
	context 'class gen name' do
		should 'generate class names' do
			assert :Total_run_check_measure == NSCA::Helper.class_name_gen( 'total run check measure')
		end

		should 'do not generate class names, if no letter' do
			assert nil == NSCA::Helper.class_name_gen( '123 321, 43 _ ?')
		end
	end
end

class TestNSCA::PerformanceData < Test::Unit::TestCase
	should 'set a subclass for new PerfData-types' do
		NSCA::PerformanceData.create 'subclass test'
		assert_nothing_raised NameError do
			assert NSCA::PerformanceData::Subclass_test, "No subclass created."
		end
	end

	def perfdata *a
		NSCA::PerformanceData.new *a
	end

	context 'Created NSCA::PerformanceData-subclasses' do
		should 'be the same like returned' do
			PA = NSCA::PerformanceData.create 'returned and subclass the same test'
			assert_equal PA, NSCA::PerformanceData::Returned_and_subclass_the_same_test
		end
		should 'not exists, if #new used' do
			pb = NSCA::PerformanceData.new 'no subclass'
			assert_raise NameError do
				NSCA::PerformanceData::No_subclass
			end
		end
		should 'have a unit if given' do
			assert :s == perfdata( 'have an unit test', :s).unit, "Not s as unit"
		end
		should 'have not a unit if not given' do
			assert nil == perfdata( 'have not an unit test', nil).unit, "Not nil as unit"
		end
		should 'have a warn thresh if given' do
			assert 3 == perfdata( 'have a warn test', nil, 3).warn, "Not 3 as warn"
		end
		should 'have not a warn thresh if not given' do
			assert nil == perfdata( 'have not a warn test', nil, nil).warn, "Not nil as warn"
		end
	end

	context 'Measure' do
		should 'work with s' do
			PC = perfdata 'something in seconds', :s
			assert PC.measure { true }.is_a?( PC), 'can not be created?'
		end

		should 'work with ms' do
			PD = perfdata 'something in mili seconds', :ms
			assert PD.measure { true }.is_a?( PD), 'can not be created?'
		end

		should 'not work with something else' do
			PE = perfdata 'something else than time', :c
			assert_raise NSCA::PerformanceData::TimeUnitExpected do
				PE.measure { true }
			end
		end

		should 'measure something between 1s..3s if i sleep 2 seconds' do
			PF = perfdata 'wait 2 seconds', :s
			pf = PF.measure { sleep 2 }
			assert (1..3).include?( pf.value), "Not in range 1s..3s: #{pf.value}s"
		end

		should 'measure something between 1000ms..3000ms if i sleep 2 seconds' do
			PG = perfdata 'wait 2000 mili second', :ms
			pf = PG.measure { sleep 2 }
			assert (1000..3000).include?( pf.value), "Not in range 1000ms..3000ms: #{pf.value}ms"
		end
	end
end

class TestNSCA::Check < Test::Unit::TestCase
	context 'Data' do
		should 'also be empty' do
			CF = NSCA::Check.new 'empty data'
			cf = CF.new
			hostname = `hostname`.chomp
			assert_equal [cf.timestamp, 3, hostname, 'empty data', 'UNKNOWN'], cf.to_a
		end

		should 'have default a timestamp. ~ -10s..10s' do
			CG = NSCA::Check.new 'default timestamp'
			cg = CG.new
			now = Time.now
			range = Time.at(now-10) .. Time.at(now+10)
			assert range.begin <= cg.timestamp && cg.timestamp <= range.end,
				"Not a valid timestamp ~now: #{cg.timestamp}"
		end
	end

	context 'Subclasses' do
		should 'be created by NSCA::Check.create' do
			CA = NSCA::Check.create 'a uniq name'
			assert_same CA, NSCA::Check::A_uniq_name
		end
	end

	context 'No Subclasses' do
		should 'be created by NSCA::Check.new' do
			CB = NSCA::Check.new 'a uniq name, too'
			assert_raise NameError, 'A class named NSCA::Check::A_uniq_name_too exists' do
				CB == NSCA::Check::A_uniq_name_too
			end
		end
	end

	context 'Clones' do
		should 'have old class as superclass' do
			CC1 = NSCA::Check.new( 'a check which will be for cloning')
			CC2 = CC1.clone
			assert_equal CC2.superclass, CC1
		end

		should 'have the same data' do
			CD1 = NSCA::Check.new 'a check for same data after cloning'
			CD2 = CD1.clone
			assert_equal CD2.to_a, CD2.to_a
		end

		should 'have the same data, except specific data' do
			CE1 = NSCA::Check.new 'a check for same data after cloning again, but...'
			CE2 = CE1.clone service: '... but the service will be changed.'
			assert_not_equal CE1.service, CE2.service
			assert_equal 'a check for same data after cloning again, but...', CE1.service
			assert_equal '... but the service will be changed.', CE2.service
			ce1_data, ce2_data = CE1.to_a, CE2.to_a
			ce1_data[0] = ce2_data[0] = 'dummy'
			assert_equal ce1_data, ce2_data
		end
	end

	context 'Perfdatas in Checks' do
		should 'be saved as symbol-key' do
			PH = NSCA::PerformanceData.new 'simplename', :ms
			CH = NSCA::Check.new 'a check with perfdata', 'hostname', [PH]
			assert_equal PH, CH.perfdatas[:'simplename']
			ch = CH.new
			assert_equal nil, ch['simplename']
			assert_equal nil,  ch[:simplename]
			a = 0
			ch.measure( 'simplename') { 0.upto( 10000) { a += 1 } }
			assert_equal ch['simplename'], ch[:simplename]
		end
	end
end
