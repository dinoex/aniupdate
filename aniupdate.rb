#!/usr/local/bin/ruby -w

# = aniupdate.rb
#
# Author::    Dirk Meyer
# Copyright:: Copyright (c) 2006-2017 Dirk Meyer
# License::   Distributes under the same terms as Ruby
# $Id$
#
# == module AniUpdate
#
# Namespace for AniUpdate UDP client for http://anidb.net/
#

require 'socket'
require 'bdb1'

# This module holds all funtcions of the AniUpdate UDP Client
module AniUpdate
  EX_USAGE = 64
  EX_DATAERR = 65
  EX_NOINPUT = 66
  EX_NOUSER = 67
  EX_NOHOST = 68
  EX_UNAVAILABLE = 69
  EX_SOFTWARE = 70
  EX_OSERR = 71
  EX_OSFILE = 72
  EX_CANTCREAT = 73
  EX_IOERR = 74
  EX_TEMPFAIL = 75
  EX_NOPERM = 77
  EX_CONFIG = 78

  # === Class Functions
  #
  #   MyConfigEntry.new
  #
  class MyConfigEntry
    attr_accessor :val
    attr_reader :name

    def initialize(name, default)
      @name = name
      @val = default
    end
  end

  # === Class Functions
  #
  #   MyConfig.new
  #   MyConfig[]( name )
  #   MyConfig.find( name )
  #   MyConfig[]=( name, val )
  #   MyConfig.parse_line(data)
  #
  class MyConfig
    attr_reader :list

    def initialize(hash)
      @list = {}
      hash.each_pair do |key, value|
        @list[key] = MyConfigEntry.new(key, value)
      end
    end

    def [](name)
      if @list[name].nil?
        STDERR.print "Config: Variable #{name} unbekannt!\n"
        return nil
      end
      @list[name].val
    end

    def find(name)
      @list[name]
    end

    def []=(name, val)
      if @list[name].nil?
        STDERR.print "Config: Variable #{name} unbekannt!\n"
      else
        @list[name].val = val
      end
    end

    def parse_line(data)
      return if data[0..0] == '#'

      # Syntax key = val
      key, text = data.split('=', 2)
      if text.nil?
        STDERR.print "Config: Variable Ausdruck #{data} unbekannt!\n"
        return
      end
      key.strip!
      text.strip!
      self[key] =
        if text[0..0] == '"'
          text[1..-1].chomp('"')
        else
          text.to_i
        end
    end

    def read(filename)
      File.open(filename).each do |line|
        parse_line(line)
      end
    end
  end

  # === Class Functions
  #
  #   LocalDB.new
  #   LocalDB.cleanup(valid_after)
  #   LocalDB.silently
  #   LocalDB.delete(key)
  #   LocalDB.write_raw(key, value)
  #   LocalDB.write(key, value)
  #   LocalDB.key(key)
  #
  class LocalDB
    # attr_accessor :filename

    def initialize(name)
      @filename = name
      @local_db_option = {
        'set_pagesize' => 1024,
        'set_cachesize' => 32 * 1024
      }
    end

    def cleanup(valid_after)
      db = BDB1::Hash.open(@filename, BDB1::WRITE, 0o0600, @local_db_option)
      # db.flock(File::LOCK_EX)
      db.each do |k, v|
        saved_text, _data = v.split('|', 2)
        saved = Time.at(saved_text.to_i)
        if saved < valid_after
          db.del(k)
          db.sync
        end
      end
      # db.flock(File::LOCK_UN)
      db.close
    rescue IOError
      STDERR.print "Database: #{@filename} nicht gefunden!\n"
      raise
      # exit EX_NOINPUT
    end

    def silently
      warn_level = $VERBOSE
      $VERBOSE = nil
      result = yield
      $VERBOSE = warn_level
      result
    end

    def delete(key)
      db = BDB1::Hash.open(
        @filename, BDB1::WRITE | BDB1::CREATE, 0o0600, @local_db_option
      )
      # db.flock(File::LOCK_EX)
      silently do
        db.db_del(key)
      end
      # db.flock(File::LOCK_UN)
      db.close
    rescue IOError
      STDERR.print "Database: #{@filename} nicht gefunden!\n"
      raise
      # exit EX_NOINPUT
    end

    def write_raw(key, value)
      db = BDB1::Hash.open(
        @filename, BDB1::WRITE | BDB1::CREATE, 0o0600, @local_db_option
      )
      # db.flock(File::LOCK_EX)
      db[key] = value
      db.sync
      # db.flock(File::LOCK_UN)
      db.close
      return value
    rescue IOError
      STDERR.print "Database: #{@filename} nicht gefunden!\n"
      raise
      # exit EX_NOINPUT
    end

    def write(key, value)
      now = Time.new.to_i
      write_raw(key, "#{now}|#{value}")
    end

    def read(key)
      db = BDB1::Hash.open(@filename, BDB1::RDONLY, 0o0600, @local_db_option)
      data = db[key]
      db.close
      return data
    rescue IOError
      STDERR.print "Database: #{@filename} nicht gefunden!\n"
      raise
      # exit EX_NOINPUT
    end
  end

  # === Class Functions
  #
  #   UdpApi.new(session_db)
  #   UdpApi.save
  #   UdpApi.delay(seconds)
  #   UdpApi.close
  #   UdpApi.open
  #   UdpApi.send_retry
  #   UdpApi.send(buffer)
  #   UdpApi.recv
  #
  class UdpApi
    SHUT_RDWR = 2
    MAX_ENTRY = 1024

    def initialize(session_db)
      @connected = false
      @next_send = 0
      @retry_count = 0
      @batch_count = 0
      @session_db = session_db
    end

    def save
      if @next_send > Time.new
        @session_db.delete('next_send')
      else
        @session_db.write('next_send', @next_send.to_i)
      end
    end

    def delay(seconds)
      @next_send += seconds
      save
    end

    def close
      return unless @connected
      @s.shutdown(SHUT_RDWR)
      @connected = false
      save
    end

    def open
      @s = UDPSocket.new
      @s.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      @s.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1)
      @s.bind('0.0.0.0', $config['Local_port'])
      @s.connect($config['Server_name'], $config['Remote_port'])
      @connected = true
      @next_send = Time.new
      data = @session_db.read('next_send')
      return if data.nil?
      _saved, text = data.split('|', 2)
      return if text.nil?
      saved_next = Time.at(text.to_i)
      @next_send = saved_next if saved_next > @next_send
    end

    def send_retry
      if @retry_buf.nil?
        STDERR.print "UDP: retry Daten verloren!\n"
        return
      end
      delay = @next_send - Time.new
      Kernel.sleep(delay) if delay > 0
      STDOUT.print "#{@retry_buf}\n" unless $config['Debug'].zero?
      @s.send(@retry_buf, 0)
      @batch_count += 1
      @next_send +=
        if $config['Batch_mode'] != 0 || @batch_count > 50
          31
        else
          3
        end
    end

    def send(buffer)
      open unless @connected
      @retry_count = $config['Retrys']
      @retry_buf = buffer
      send_retry
    end

    def recv
      open unless @connected
      begin
        Kernel.select([@s], nil, nil, $config['Timeout'])
        data = @s.recvfrom(MAX_ENTRY)
        if data.nil?
          #  (errno == ECONNREFUSED)
          if data.nil?
            @next_send = Time.new
            @next_send += 30 * 60
            save
            STDERR.print "UDP: Verbindung abgewiesen!\n"
            STDERR.print "recv #{data}\n"
            exit EX_TEMPFAIL
          end
          #  (errno == EAGAIN)
          if @retry_count.zero? && data.nil?
            STDERR.print "UDP: Verbindung fehlgeschlagen!\n"
            STDERR.print "recv #{data}\n"
            exit EX_OSERR
          end
          STDERR.print "recv #{data}\n"
          @retry_count -= 1
          send_retry
          return recv
        end
        # llen.zero?
        if data.nil?
          @retry_count -= 1
          send_retry
          return recv
        end
        STDOUT.print "#{data[0]}\n" unless $config['Debug'].zero?
        return data[0]
        # rescue StandardError
        # @retry_count -= 1
        # send_retry
        # retry
      end
    end
  end

  # === Class Functions
  #
  #   FileKey.new
  #   FileKey.may_ed2klink(link)
  #   FileKey.must_ed2klink(key, try)
  #   FileKey.generate_hash(filename)
  #   FileKey.filename_to_hash(key)
  #
  class FileKey
    REGEX_HASH = /ed2k[:][^|]*[|][^|]*[|][^|]*[|]([^|]*)[|]([^|]*)[|]/
    attr_reader :hash_key
    attr_reader :hash_size
    attr_reader :hash_md4
    attr_reader :hash_link
    attr_reader :hash_dbkey
    attr_reader :hash_anidbkey

    def initialize
      @hash_key = nil
      @hash_size = nil
      @hash_md4 = nil
      @hash_link = nil
      @hash_dbkey = nil
      @hash_anidbkey = nil
      @names_db = LocalDB.new($config['Names_db'])
    end

    # in:
    # ed2k://|file|[PM]Princess_Tutu_13[A0BC1BC8].avi|\
    #   146810880|0436df97e7fe25b620edb25380717479|
    # out:
    # 146810880
    # 0436df97e7fe25b620edb25380717479
    def may_ed2klink(link)
      link.scan(REGEX_HASH) do |entry|
        return false if entry[0].nil? || entry[1].nil?
        @hash_size = entry[0]
        @hash_md4 = entry[1].downcase
        @hash_link = link
        @hash_dbkey = "#{hash_size}|#{hash_md4}"
        @hash_anidbkey = "size=#{hash_size}&ed2k=#{hash_md4}"
        return true
      end
      false
    end

    def must_ed2klink(key, try)
      ok = may_ed2klink(key)
      STDERR.print "File not an ed2k link: #{try}\n" if !ok && !try.nil?
    end

    def generate_hash(filename)
      cmdline = $config['Hash_program']
      cmdline << " '"
      cmdline << filename
      cmdline << "'"
      begin
        return IO.popen(cmdline).gets
      rescue IOError
        STDERR.print "cannot execute hash from program: #{cmdline}\n"
        return nil
      end
    end

    def filename_to_hash(key)
      # cached value
      return if key == @hash_key
      # new value
      @hash_key = key
      @hash_size = nil
      @hash_md4 = nil
      @hash_link = nil

      return if may_ed2klink(key)

      base = key.sub(/^.*\//, '')
      data = @names_db.read(base)
      unless data.nil?
        must_ed2klink(data, base)
        return
      end
      data = generate_hash(key)
      return if data.nil?
      @names_db.write(base, data)
      must_ed2klink(data, base)
    end
  end

  # === Class Functions
  #
  #   AnidbApi.new
  #   AnidbApi.status
  #   AnidbApi.nosession
  #   AnidbApi.logout
  #   AnidbApi.delay_login
  #   AnidbApi.auth_request
  #   AnidbApi.login
  #   AnidbApi.ping
  #   AnidbApi.fetch(db, cmd, key, force)
  #   AnidbApi.animes(key, force)
  #   AnidbApi.episodes(key, force)
  #   AnidbApi.groups(key, force)
  #   AnidbApi.files(key, force)
  #   AnidbApi.mylist(key, force)
  #   AnidbApi.add(key, edit)
  #
  class AnidbApi
    def initialize
      @tag = '##nosession##'
      @auth_delay = 0
      @server_status = ''
      @session = nil
      @session_db = LocalDB.new($config['Session_db'])
      @network = UdpApi.new(@session_db)
      @animes_db = LocalDB.new($config['Animes_db'])
      @episodes_db = LocalDB.new($config['Episodes_db'])
      @groups_db = LocalDB.new($config['Groups_db'])
      @files_db = LocalDB.new($config['Files_db'])
      @mylist_db = LocalDB.new($config['Mylist_db'])
      @hash = FileKey.new
    end

    def status
      @mbuf = @rbuf.sub(/#{@tag} /, '')
      @server_status = @mbuf[0..2]
    end

    def nosession
      return if @session.nil?
      @session_db.delete('session')
      @session = nil
    end

    def logout
      return if @session.nil?
      @sbuf = "LOGOUT s=#{@session}&tag=#{@tag}\n"
      nosession
      @network.send(@sbuf)
      @rbuf = @network.recv
      status
      return if @server_status == '203' || @server_status == '403'

      # try to close all sessions
      @sbuf = "LOGOUT\n"
      @server_status = status
      @network.send(@sbuf)
      @rbuf = @network.recv
      @network.close
      status
    end

    def delay_login
      @auth_delay += 1
      case @auth_delay
      when 1
        @network.delay(30)
      when 2
        @network.delay(2 * 60)
      when 3
        @network.delay(5 * 60)
      when 4
        @network.delay(10 * 60)
      else
        add = 30 * 60
        add << (@auth_delay - 4)
        @network.delay(add)
      end
    end

    def auth_request
      auth = "AUTH user=#{$config['User']}&pass=#{$config['Password']}"
      auth << '&protover=3&client=aniupdate&clientver=3'
      auth << "&enc=UTF-8&tag=#{@tag}\n"
    end

    def login
      nosession if @session.nil?
      @tag = $config['User']

      data = @session_db.read('session')
      unless data.nil?
        saved, text = data.split('|', 2)
        unless text.nil?
          saved_time = Time.at(saved.to_i)
          valid_time = Time.new - (24 * 60 * 60)
          if saved_time > valid_time
            @session = text
            return
          end
        end
      end

      @sbuf = auth_request
      @network.send(@sbuf)
      @rbuf = @network.recv
      status
      case @server_status
      when '200', '201'
        STDERR.print "Server returns: #{@rbuf}\n"
      when '503', '504', '505'
        delay_login
        STDERR.print "Server returns: #{@rbuf}\n"
      when '500', '501', '502', '506'
        delay_login
        STDERR.print "Server returns: #{@rbuf}\n"
        exit EX_NOUSER
      when '507', '555', '598', '601', '666'
        @network.delay(30 * 60)
        STDERR.print "Server returns: #{@rbuf}\n"
        exit EX_TEMPFAIL
      else
        STDERR.print "Server returns: #{@rbuf}\n"
        exit EX_TEMPFAIL
      end

      _saved, text, _rest = @mbuf.split(' ', 3)
      if text.nil?
        STDERR.print "Server returns: #{@rbuf}\n"
        exit EX_TEMPFAIL
      end
      @session = text
      @auth_delay = 0
      @session_db.write('session', @session)
    end

    def ping
      @sbuf = "PING tag=#{@tag}\n"
      @network.send(@sbuf)
      @rbuf = @network.recv
      status
      STDERR.print "Server returns: #{@rbuf}\n" if @server_status != '300'
    end

    def fetch(db, cmd, key, force)
      if $config['Cache_ignore'].zero? && force.zero? && !db.nil?
        data = db.read(key)
        return data unless data.nil?
      end

      login if @session.nil?
      return nil if @session.nil?

      @sbuf = "#{cmd}&s=#{@session}&tag=#{@tag}\n"
      @network.send(@sbuf)
      @rbuf = @network.recv
      status
      case @server_status
      when '210', '220', '221', '230', '240', '250'
        # update vaild session
        @session_db.write('session', @session)
      when '311'
        # update vaild session
        @session_db.write('session', @session)
        return nil
      when '501', '506'
        nosession
        return fetch(db, cmd, key, force)
      when '310', '320', '321', '322', '330', '340', '350'
        STDERR.print "Server returns: #{@rbuf}\n"
        return nil
      when '507', '555', '601', '666'
        @network.delay(30 * 60)
        STDERR.print "Server returns: #{@rbuf}\n"
        exit EX_TEMPFAIL
      when '500', '502', '504'
        delay_login
        STDERR.print "Server returns: #{@rbuf}\n"
        exit EX_NOUSER
      else
        STDERR.print "Server returns: #{@rbuf}\n"
        return nil
      end

      return @rbuf if db.nil?
      _status, text, _rest = @mbuf.split("\n", 3)
      if text.nil?
        STDERR.print "Server returns: #{@rbuf}\n"
        return nil
      end
      db.write(key, text)
    end

    def animes(key, force)
      STDOUT.print "animes: #{key}\n" unless $config['Verbose'].zero?
      @cbuf = "ANIME aid=#{key}"
      fetch(@animes_db, @cbuf, key, force)
    end

    def episodes(key, force)
      STDOUT.print "episodes: #{key}\n" unless $config['Verbose'].zero?
      @cbuf = "EPISODE eid=#{key}"
      fetch(@episodes_db, @cbuf, key, force)
    end

    def groups(key, force)
      STDOUT.print "groups: #{key}\n" unless $config['Verbose'].zero?
      @cbuf = "GROUP gid=#{key}"
      fetch(@groups_db, @cbuf, key, force)
    end

    def files(key, force)
      STDOUT.print "files: #{key}\n" unless $config['Verbose'].zero?
      @hash.filename_to_hash(key)
      return nil if @hash.hash_dbkey.nil?
      @cbuf = "FILE #{@hash.hash_anidbkey}"
      fetch(@files_db, @cbuf, @hash.hash_dbkey, force)
    end

    def mylist(key, force)
      STDOUT.print "mylist: #{key}\n" unless $config['Verbose'].zero?
      @hash.filename_to_hash(key)
      return nil if @hash.hash_dbkey.nil?
      @cbuf = "MYLIST #{@hash.hash_anidbkey}"
      fetch(@mylist_db, @cbuf, @hash.hash_dbkey, force)
    end

    def add(key, edit)
      STDOUT.print "add: #{key}\n" unless $config['Verbose'].zero?
      @hash.filename_to_hash(key)
      return nil if @hash.hash_dbkey.nil?
      @cbuf = "MYLISTADD #{@hash.hash_anidbkey}"
      if edit.nil?
        @cbuf << "&state=#{$config['Add_state']}"
        @cbuf << "&viewed=#{$config['Add_viewed']}"
        @cbuf << "&source=#{$config['Add_source']}"
        @cbuf << "&storage=#{$config['Add_storage']}"
        @cbuf << "&other=#{$config['Add_other']}"
      else
        @cbuf << "&state=#{edit['state']}"
        @cbuf << "&viewed=#{edit['viewdate']}"
        @cbuf << "&source=#{edit['source']}"
        @cbuf << "&storage=#{edit['storage']}"
        @cbuf << "&other=#{edit['other']}"
        @cbuf << '&edit=1'
      end
      fetch(nil, @cbuf, @hash.hash_dbkey, 0)
    end
  end

  # === Class Functions
  #
  #   AniUpdate.new
  #   AniUpdate.print_date(prefix, seconds)
  #   AniUpdate.show_anidb(info, key, data)
  #   AniUpdate.mylist_decode(key, data)
  #   AniUpdate.mylist_edit(mylist, changes)
  #   AniUpdate.usage
  #   AniUpdate.command_config(argv)
  #   AniUpdate.command_options(argv)
  #   AniUpdate.command_run(argv)
  #   AniUpdate.
  #   AniUpdate.
  #   AniUpdate.
  #   AniUpdate.logout
  #
  class AniUpdate
    RESPONSE_MYLIST = [
      'lid',
      'fid',
      'eid',
      'aid',
      'gid',
      'date',
      'state',
      'viewdate',
      'storage',
      'source',
      'other'
    ].freeze

    RESPONSE_FILE = [
      'fid',
      'aid',
      'eid',
      'gid',
      'state',
      'size',
      'ed2k',
      'anidbfilename'
    ].freeze

    RESPONSE_ANIME = [
      'aid',
      'eps_total',
      'eps_normal',
      'eps_special',
      'rating',
      'votes',
      'tmprating',
      'itmpvotes',
      'review_rating',
      'reviews',
      'year',
      'type',
      'romaji',
      'kanji',
      'english',
      'other',
      'short_names',
      'synonyms',
      'category_list'
    ].freeze

    RESPONSE_EPISODE = [
      'eid',
      'aid',
      'length',
      'rating',
      'votes',
      'epno',
      'english',
      'romaji',
      'kanji'
    ].freeze

    RESPONSE_GROUP = [
      'gid',
      'rating',
      'votes',
      'acount',
      'fcount',
      'name',
      'short',
      'chan',
      'irc',
      'url'
    ].freeze

    MYLIST_STATES = [
      'unknown',
      'on hdd',
      'on cd',
      'deleted',
      'shared',
      'release'
    ].freeze

    INFO_CRC = [
      'unknown',
      'ok',
      'bad',
      'unknown'
    ].freeze

    $config = MyConfig.new(
      # Config
      'Config_file' => '.aniupdate',

      # Databases
      'Animes_db' => 'animes.db',
      'Episodes_db' => 'episodes.db',
      'Groups_db' => 'groups.db',
      'Files_db' => 'files.db',
      'Mylist_db' => 'mylist.db',
      'Names_db' => 'names.db',
      'Session_db' => '.session.db',

      # Account
      'Server_name' => 'localhost',
      'Remote_port' => 9000,
      'Local_port' => 9000,
      'User' => nil,
      'Password' => nil,

      # Network
      'Keep_session' => 0,
      'Retrys' => 2,
      'Timeout' => 30,

      # Options
      'Debug' => 0,
      'Verbose' => 0,
      'Quiet' => 0,
      'Batch_mode' => 0,
      'Cache_ignore' => 0,

      # External Data and Tools
      'Date_format' => '%Y-%m-%d %H:%M:%S',
      'Hash_program' => 'edonkey-hash',

      # Default mylist
      'Add_other' => '',
      'Add_source' => '',
      'Add_storage' => '',
      'Add_state' => 1,
      'Add_viewed' => nil
    )

    def initialize
      begin
        command_config(ARGV)
      rescue StandardError
        usage
      end
      $config.read $config['Config_file']
      begin
        command_options(ARGV)
      rescue StandardError
        usage
      end
      if $config['User'].nil?
        STDERR.print "User not set\n"
        exit EX_CONFIG
      end
      if $config['Password'].nil?
        STDERR.print "Password not set\n"
        exit EX_CONFIG
      end
      @anidb = AnidbApi.new
      @hash = FileKey.new
    end

    def print_date(prefix, seconds)
      return if seconds.nil?
      lsec = seconds.to_i
      return if lsec.zero?

      text = Time.at(lsec).strftime($config['Date_format'])
      printf("%stext: %s\n", prefix, text)
    end

    def show_anidb(info, key, data)
      files = false
      files = true if info[0] == 'fid'
      mylist = false
      mylist = true if info[0] == 'lid'
      if files || mylist
        @hash.filename_to_hash(key)
        unless @hash.hash_size.nil?
          printf("%s: %s\n", 'size', @hash.hash_size)
          printf("%s: %s\n", 'ed2khash', @hash.hash_md4)
        end
      end
      linfo = ['cached'] + info
      field = data.split('|')
      linfo.each_index do |i|
        printf("%s: %s\n", linfo[i], field[i])
        case linfo[i]
        when 'cached'
          print_date(linfo[i], field[i])
        when /date$/
          print_date(linfo[i], field[i])
        when 'state'
          st = field[i].to_i
          if files
            unless MYLIST_STATES[st].nil?
              printf("%s: %s\n", 'statetext', MYLIST_STATES[st])
            end
          end
          if mylist
            crc = st & 0x03
            rver = st & 0x3c
            printf("%s: %s\n", 'crc', INFO_CRC[crc])
            version =
              case rver
              when 0
                '1'
              when 1
                '2'
              when 2
                '3'
              when 4
                '4'
              when 8
                '5'
              else
                'unknown'
              end
            printf("%s: %s\n", 'version', version)
            printf("censored: uncut\n") if (st & 0x40) != 0
            printf("censored: censored\n") if (st & 80) != 0
          end
        end
      end
      printf("\n")
    end

    def mylist_decode(key, data)
      @hash.filename_to_hash(key)
      return nil if @hash.hash_size.nil?

      linfo = ['cached'] + RESPONSE_MYLIST
      mylist = {}
      field = data.split('|')
      linfo.each_index do |i|
        mylist[linfo[i]] = field[i]
      end
      mylist
    end

    def mylist_edit(mylist, changes)
      return nil if changes.nil?

      key, value = changes.split('=', 2)
      return nil if value.nil?
      case key
      when /^o/
        mylist['other'] = value.to_s
      when /^so/
        mylist['source'] = value.to_s
      when /^sto/
        mylist['storage'] = value.to_s
      when /^sta/
        known = MYLIST_STATES.index(value.to_s)
        mylist['state'] =
          if known.nil?
            value.to_s
          else
            known.to_s
          end
      else
        return nil
      end
      mylist
    end

    def usage
      STDERR.print('

Usage: aniupdate [options] [...] commands [...]

options:
-debug            show datagramms
-verbose          show files processed
-quiet            dont print data
-f <config>       set name of config file, default .aniudate
--<name>=<value>  overrite config with given value
-local <port>     set local port number, default 9000
-remote <port>    set remote port number, default 9000
-server <name>    set remote host, default anidb.ath.cx
-user             set userid

commands:
+ping                    test communication
+mylist ed2klink [...]   add files to mylist
+read ed2klink [...]     read mylist info
+view ed2klink [...]     set files as viewed (date will not be preserved)
+unview ed2klink [...]   set files as unviewed
+write key=value ed2klink [...]   change a field in mylist
+anime id [...]          read anime info
+episode id [...]        read episode info
+group id [...]          read group info
+file ed2klink [...]     read file info

')
      exit EX_USAGE
    end

    def command_config(argv)
      largv = []
      largv += argv
      loop do
        arg = largv.shift
        return if arg.nil?
        next if arg[0..0] != '-'
        case arg[1..1].downcase
        when 'd'
          $config['Debug'] = 1
        when 'f'
          $config['Config_file'] = largv.shift
        when 'q'
          $config['Quiet'] = 1
        when 'v'
          $config['Verbose'] = 1
        end
      end
    end

    def command_options(argv)
      fc = ''
      largv = []
      largv += argv
      loop do
        arg = largv.shift
        return if arg.nil?
        if arg[0..0] == '-'
          case arg[1..1].downcase
          when '-'
            $config.parse_line(arg[2..-1])
          when 'd'
            $config['Debug'] = 1
          when 'f'
            next
          when 'l'
            $config['Local_port'] = largv.shift
          when 'p'
            $config['Password'] = largv.shift
          when 'q'
            $config['Quiet'] = 1
          when 'r'
            $config['Remote_port'] = largv.shift
          when 's'
            $config['Server_name'] = largv.shift
          when 'u'
            $config['User'] = largv.shift
          when 'v'
            $config['Verbose'] = 1
          else
            usage
          end
          next
        end
        # sntax check
        if arg[0..0] == '+'
          fc = arg[1..1].downcase
          case fc
          when 'a', 'e', 'f', 'g', 'm', 'p', 'r', 'u', 'v'
            next
          when 'w'
            largv.shift
          else
            usage
          end
          next
        end
        case fc
        when 'a', 'e', 'f', 'g', 'm', 'r', 'u', 'v', 'w'
          next
        else
          usage
        end
      end
    end

    def command_run(argv)
      write = nil
      fc = ''
      largv = []
      largv += argv
      loop do
        arg = largv.shift
        return if arg.nil?
        next if arg[0..0] == '-'
        if arg[0..0] == '+'
          fc = arg[1..1].downcase
          case fc
          when 'p'
            @anidb.ping
          when 'w'
            write = largv.shift
          end
          next
        end
        case fc
        when 'a'
          data = @anidb.animes(arg, 0)
          next if data.nil? || ($config['Quiet'] != 0)
          show_anidb(RESPONSE_ANIME, arg, data)
        when 'e'
          data = @anidb.episodes(arg, 0)
          next if data.nil? || ($config['Quiet'] != 0)
          show_anidb(RESPONSE_EPISODE, arg, data)
        when 'f'
          data = @anidb.files(arg, 0)
          next if data.nil? || ($config['Quiet'] != 0)
          show_anidb(RESPONSE_FILE, arg, data)
        when 'g'
          data = @anidb.groups(arg, 0)
          next if data.nil? || ($config['Quiet'] != 0)
          show_anidb(RESPONSE_GROUP, arg, data)
        when 'm'
          @anidb.add(arg, nil)
        when 'r'
          data = @anidb.mylist(arg, 0)
          next if data.nil? || ($config['Quiet'] != 0)
          show_anidb(RESPONSE_MYLIST, arg, data)
        when 'u'
          data = @anidb.mylist(arg, 0)
          next if data.nil?
          mylist_entry = mylist_decode(arg, data)
          mylist_entry['viewdate'] = '0'
          @anidb.add(arg, mylist_entry)
          @anidb.mylist(arg, 1)
        when 'v'
          data = @anidb.mylist(arg, 0)
          next if data.nil?
          mylist_entry = mylist_decode(arg, data)
          next if mylist_entry['viewdate'] != '0'
          mylist_entry['viewdate'] = '1'
          @anidb.add(arg, mylist_entry)
          @anidb.mylist(arg, 1)
        when 'w'
          data = @anidb.mylist(arg, 0)
          next if data.nil?
          mylist_entry = mylist_decode(arg, data)
          mylist_entry = mylist_edit(mylist_entry, write)
          # We have to reset viewdate
          mylist_entry['viewdate'] = '1' if mylist_entry['viewdate'] != '0'
          usage if mylist_entry.nil?
          @anidb.add(arg, mylist_entry)
          @anidb.mylist(arg, 1)
        end
      end
    end

    def logout
      @anidb.logout if $config['Keep_session'].zero?
    end
  end
end

app = AniUpdate::AniUpdate.new
app.command_run(ARGV)
app.logout
exit 0

# eof
