# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def checkcase(keys, target)
  for key in keys
    key1 = key
    if key1.downcase == target
      return key
    end
  end
  return target
end

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html

  # debugging
=begin
  puts "Printing event: "
  puts event
  puts event['httpMethod']
=end
  
  # check if httpMethod field is present
  w_httpmethod = checkcase(event.keys, 'httpmethod')
  begin
  # event.fetch('httpMethod')
    event.fetch(w_httpmethod)
  rescue KeyError
    puts "httpMethod not in event"
    response(body: event, status: 405)
  else
    #if event['httpMethod']!= 'POST' and event['httpMethod']!= 'GET'
    if event[w_httpmethod] != 'POST' and event[w_httpmethod] != 'GET'
      puts "neither POST nor GET request"
      response(body: event, status: 405)

    # POST
    #elsif event['httpMethod'] == 'POST'
    elsif event[w_httpmethod] == 'POST' 
      puts "detected request as POST"
      w_headers = checkcase(event.keys, 'headers')
      begin
        #event.fetch('headers')
        event.fetch(w_headers)
      rescue KeyError
        puts "No headers"
        response(body: event, status: 405)
      else

        ## new way
        header_hash = {}
        event['headers'].each do |k,v|
          header_hash[k.downcase] = v
        end
        puts "header_hash", header_hash
        #w_contenttype = header_hash['content-type']
        #puts "w_contenttype", w_contenttype
        begin
          #event['headers'].fetch('Content-Type')
          #event[w_headers].fetch('Content-Type')
          header_hash.fetch('content-type')
        rescue KeyError
          puts "No Content-Type"
          response(body: event, status: 405)
        else
          if header_hash['content-type'] != 'application/json'
            puts "Invalid Content-Type"
            response(body: event, status: 415)
          else
            begin
              event.fetch('body')
            rescue KeyError
              puts "no body"
              response(body: event, status: 405)
            else
              begin
                JSON.parse(event['body'])
              rescue => e
                puts e
                puts "body not JSON"
                response(body: "", status: 422)
              else
                payload = {data: JSON.parse(event['body']), exp: Time.now.to_i + 5 , nbf: Time.now.to_i + 2}
                token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
                json_doc = {'token' => "#{token}"}
                response(body: json_doc, status: 201)
              end
            end
          end
        end
      end

    # GET
    elsif event[w_httpmethod] == "GET"
      puts "detected request as GET"
      if event['path'] == '/token'
        response(body: event, status: 405)
      elsif event['path'] != '/'
        response(body: event, status: 404)
      else
        begin
          event.fetch('headers')
          event.fetch('httpMethod')
          event.fetch('path')
        rescue KeyError
          response(body: event, status: 405)
        else
          begin
            event['headers'].fetch('Authorization')
          rescue KeyError
            puts "Authorization is missing"
            response(body: event, status: 403)
          else
            token = event['headers']['Authorization'].split
            puts "token: ", token
            if token[0] != 'Bearer'
              puts "word Bearer missing"
              response(body: event, status: 403)
            else
              t = token[1]
              begin
                JWT.decode(t, ENV['JWT_SECRET'], true)
              rescue JWT::DecodeError => e
                puts e
                if e.class == JWT::ExpiredSignature or e.class == JWT::ImmatureSignature
                  response(body: event, status: 401)
                else
                  response(body: event, status: 403)
                end
              else
                payload = JWT.decode(t, ENV['JWT_SECRET'], true)
                payload = payload[0]
                begin
                  payload.fetch('data')
                rescue KeyError
                  puts "data field missing in payload"
                  response(body: event, status: 405)
                else
                  response(body: payload['data'], status: 200)
                end
              end
            end
          end
        end
      end
    end
  end
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end

