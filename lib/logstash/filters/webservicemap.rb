# encoding: utf-8
require 'logstash/filters/base'
require 'logstash/namespace'
require 'open-uri'
require 'digest/sha1'
require 'json'
require 'csv'

# A general search and replace tool which uses a Web service with a YAML, CSV or JSON response to determine replacement values.
#
# The map entries can be specified with a Web service who your request produces a YML, CSV or JSON response.
#
# Operationally, if the event field specified in the `field` configuration
# matches the EXACT contents of a map entry key, the field's value will be substituted
# with the matched key's value from the map.
#
# By default, the webservicemap filter will replace the contents of the
# maching event field (in-place). However, by using the `destination`
# configuration item, you may also specify a target event field to
# populate with the new mapd value.

class LogStash::Filters::WebServiceMap < LogStash::Filters::Base
  config_name "webservicemap"

  # The name of the logstash event field containing the value to be compared for a
  # match by the map filter (e.g. `message`, `host`, `response_code`). 
  # 
  # If this field is an array, only the first value will be used.
  config :field, :validate => :string, :required => true

  # If the destination (or target) field already exists, this configuration item specifies
  # whether the filter should skip mapping (default) or overwrite the target field
  # value with the new mapping value.
  config :override, :validate => :boolean, :default => false

  # The full URI path of a Web service who generates an JSON, yml or CSV format response.
  # requires to append as suffix the format type. Ex: http://localhost:8080/geoPoints?type=json
  # http://localhost:8080/geoPoints/json
  # http://localhost:8080/geoPoints/csv
  # If no suffix matches, defaults to YAML
  config :map_url, :validate => :string, :required => true

  # When using a map file or url, this setting will indicate how frequently
  # (in seconds) logstash will check the YAML file or url for updates.
  config :refresh_interval, :validate => :number, :default => 300

  # The destination field you wish to populate with the mapd code. The default
  # is a field named `mapping`. Set this to the same value as source if you want
  # to do a substitution, in this case filter will allways succeed. This will clobber
  # the old value of the source field! 
  config :destination, :validate => :string, :default => "mapping"

  # In case no mapping occurs in the event (no matches), this will add a default
  # mapping string, which will always populate `field`, if the match failed.
  #
  # For example, if we have configured `fallback => "no match"`, using this map:
  # [source,ruby]
  #     foo: bar
  #
  # Then, if logstash received an event with the field `foo` set to `bar`, the destination
  # field would be set to `bar`. However, if logstash received an event with `foo` set to `nope`,
  # then the destination field would still be populated, but with the value of `no match`.
  # This configuration can be dynamic and include parts of the event using the `%{field}` syntax.
  config :fallback, :validate => :string

  def get_map
    @my_map
  end

  def set_map(map)
    @my_map = map;
  end

  public
  def register
    @my_map = {}
    @next_refresh = Time.now + @refresh_interval
    download_ws(@map_url, true)
    @logger.debug? and @logger.debug("#{self.class.name}: map - ", :map => get_map)
    type = 'Exact'
    @logger.debug? and @logger.debug("#{self.class.name}: map mapping method - "+type)
  end

  # def register

  def json_loader(data)
    get_map.merge!(JSON.parse(File.read(data)))
  end

  def csv_loader(data)
    data = CSV.read(data).inject(Hash.new) do |acc, v|
      acc[v[0]] = v[1]
      acc
    end
    get_map.merge!(data)
  end

  def yml_loader(data)
    get_map.merge!(YAML.load_file(data))
  end

  def load_file(registering, extension, data)
    begin
      if extension.equal?('.json')
        return json_loader(data)
      elsif extension.end_with?('.csv')
        return csv_loader(data)
      end
      yml_loader(data)
    rescue Exception => _
      if registering
        raise "#{self.class.name}: Bad Syntax in map file #{file_name}"
      else
        @logger.warn("#{self.class.name}: Bad Syntax in map file, continuing with old map", :map_path => file_name)
      end
    end
  end

  def get_extension(path)
    if path.end_with?('json')
      return '.json'
    elsif path.end_with?('csv')
      return '.csv'
    end
    '.yml'
  end

  public
  def download_ws(path, registering=false)
    extension = get_extension(path)
    temp_extension = '_temp'+extension;
    file_name = Digest::SHA1.hexdigest path
    begin
      File.open(file_name+temp_extension, 'wb') do |saved_file|
        open(path, 'rb') do |read_file|
          saved_file.write(read_file.read)
        end
      end
    rescue Exception => _
      if registering
        raise "#{self.class.name}: Failed to initialize with #{file_name} and path #{path}"
      end
      @logger.warn("#{self.class.name}: Something happened with URL. Continuing with old map", :map_path => file_name, :path => path)
    end

    begin
      load_file(registering, extension, file_name+temp_extension)
      FileUtils.mv(file_name+temp_extension, file_name+extension)
    rescue Exception => _
      FileUtils.rm_f(file_name+temp_extension)
    end
  end

  # def download_yaml

  public
  def filter(event)
    if @next_refresh < Time.now
      download_ws(@map_url)
      @next_refresh = Time.now + @refresh_interval
      @logger.info('downloading and refreshing map file')
    end

    return unless event.include?(@field) # Skip mapping in case event does not have @event field.
    return if event.include?(@destination) and not @override # Skip mapping in case @destination field already exists and @override is disabled.

    begin
      source = event[@field].is_a?(Array) ? event[@field].first.to_s : event[@field].to_s
      matched = false
      if get_map.include?(source)
        event[@destination] = get_map[source]
        matched = true
      end

      if not matched and @fallback
        event[@destination] = event.sprintf(@fallback)
        matched = true
      end
      filter_matched(event) if matched or @field == @destination
    rescue Exception => e
      @logger.error('Something went wrong when attempting to map from my_map', :exception => e, :field => @field, :event => event)
    end
  end # def filter
end # class LogStash::Filters::WebServiceMap
