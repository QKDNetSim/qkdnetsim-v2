/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015 Magister Solutions
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Miralem Mehic <miralem.mehic@ieee.org>
 *
 */

#include <ns3/log.h>
#include <ns3/packet.h>
#include <sstream>
#include "ns3/http-header.h"

NS_LOG_COMPONENT_DEFINE ("HttpHeader");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (HttpHeader);

HttpHeader::HttpHeader ()
  : Header (),
  m_status(0),
  m_contentLength (0),
  m_headerSize (0)
{
  NS_LOG_FUNCTION (this);
  m_fragmented = false;
}

void
HttpHeader::CreateRequest(
  const std::string& url,
  const std::string& method,
  const std::map<std::string, std::string>& parameters,
  const std::vector<std::string>& headers)
{
  NS_LOG_FUNCTION(this << "48");

  std::string body;
  bool first = true;

  for (const auto& parameter : parameters)
  {
      if (!first) body += "&";
      first = false;

      body += urlEncode(parameter.first) + "=" + urlEncode(parameter.second);
  }

  CreateRequest(url, method, body, headers);
}

void
HttpHeader::CreateRequest(
  const std::string& url,
  const std::string& method,
  const std::string& body,
  const std::vector<std::string>& headers)
{
  NS_LOG_FUNCTION(this << "71");

  CreateRequest(
    url, 
    method,
    std::vector<uint8_t>(body.begin(), body.end()),
    headers 
  );
}

void
HttpHeader::CreateRequest(
  const std::string& url,
  const std::string& method,
  const std::vector<uint8_t>& body,
  const std::vector<std::string>& headers
) { 

  NS_LOG_FUNCTION(this << "89" << url << method);
  SetUri(url);
  SetMethod(method);
  m_headers = headers;

  std::string headerData = method + " " + m_path + " HTTP/1.1\r\n";

  for (const std::string& header : headers){
    headerData += header + "\r\n";
  }

  headerData += "Host: " + m_domain + "\r\n"
    "Content-Length: " + std::to_string(body.size()) + "\r\n";

  //if(body.size()>300) headerData += "Transfer-Encoding: chunked\r\n";
  
  headerData += "Accept-Language: en-us,en;q=0.5\r\n";
  headerData += "Accept-Encoding: gzip,deflate\r\n";
  headerData += "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n";
  headerData += "Keep-Alive: 300\r\n";
  headerData += "Connection: keep-alive\r\n";
  headerData += "Cookie: PHPSESSID=r2t5uvjq435r4q7ib3vtdjq120\r\n";
  headerData += "Pragma: no-cache\r\n";
  headerData += "Cache-Control: no-cache\r\n" "\r\n";


 
  m_allData.clear();
  m_payload.clear();
 
  //add headers
  std::vector<uint8_t> requestData(headerData.begin(), headerData.end());
  m_allData = requestData; 

  //add payload
  m_allData.insert(m_allData.end(), body.begin(), body.end());
  m_payload.insert(m_payload.end(), body.begin(), body.end());

  NS_LOG_FUNCTION(this << "headerData: " << headerData);
  NS_LOG_FUNCTION(this << "headerData.size(): " << headerData.size());
  NS_LOG_FUNCTION(this << "m_payload.size(): " << m_payload.size());
  NS_LOG_FUNCTION(this << "m_allData.size(): " << m_allData.size());

  m_headerSize = headerData.size();
  m_contentLength = m_payload.size();

}
 

void
HttpHeader::CreateResponse(
  const HttpHeader::HttpStatus status,
  const std::string& body,
  const std::vector<std::string>& headers)
{
    CreateResponse(
      status,
      std::vector<uint8_t>(body.begin(), body.end()),
      headers 
    );
}

void
HttpHeader::CreateResponse(
  const HttpHeader::HttpStatus status,
  const std::vector<uint8_t>& body,
  const std::vector<std::string>& headers
) { 

  std::string bodyString = std::string{body.begin(), body.end()};

  NS_LOG_FUNCTION( this << bodyString << std::to_string(body.size()) );

  SetStatus(status);
  m_headers = headers;

  std::string headerData = "HTTP/1.1 " + std::to_string(m_status) + " " + GetStatusString() + "\r\n";

  for (const std::string& header : headers){
    headerData += header + "\r\n";
  }

  headerData += "Server: nginx/1.17.0 (Ubuntu)\r\n"
    "Content-Length: " + std::to_string(body.size()) + "\r\n";

  //if(body.size()>300) headerData += "Transfer-Encoding: chunked\r\n";
  
  headerData += "Date: Sat, 28 Nov 2021 04:36:25 GMT\r\n";
  headerData += "Connection: close\r\n";
  headerData += "Pragma: public\r\n";
  headerData += "Etag: pub1259380237;gz\r\n";
  headerData += "Cache-Control: max-age=3600, public\r\n";
  headerData += "Content-Encoding: gzip\r\n";
  headerData += "Vary: Accept-Encoding, Cookie\r\n" "\r\n";


  m_allData.clear();
  m_payload.clear();
  
  //add headers
  std::vector<uint8_t> requestData(headerData.begin(), headerData.end());
  m_allData = requestData; 

  //add payload
  m_allData.insert(m_allData.end(), body.begin(), body.end());
  m_payload.insert(m_payload.end(), body.begin(), body.end());

  NS_LOG_FUNCTION( this << "m_allData.size(): " << m_allData.size() << GetPayloadString() );
  m_contentLength = m_allData.size();

}

void
HttpHeader::ParseResponse()
{   
    constexpr std::uint8_t crlf[] = {'\r', '\n'}; 
    std::vector<std::uint8_t> responseData = m_allData;
    bool firstLine = true;
    bool parsedHeaders = false;
    bool contentLengthReceived = false; 
    bool chunkedResponse = false;
    std::size_t expectedChunkSize = 0;
    bool removeCrlfAfterChunk = false;
    m_headerSize = 0;

    // read the response
    if (!parsedHeaders)
        for (;;)
        {
            const auto i = std::search(responseData.begin(), responseData.end(), std::begin(crlf), std::end(crlf));

            // didn't find a newline
            if (i == responseData.end()) break;

            const std::string line(responseData.begin(), i);
            responseData.erase(responseData.begin(), i + 2);
 

            NS_LOG_FUNCTION(this << "221: " << "\t" << line << line.size() << m_headerSize );

            // empty line indicates the end of the header section
            if (line.empty())
            {
                parsedHeaders = true;
                break;
            }
            else if (firstLine) // first line
            {
                firstLine = false;
                m_headerSize += line.size();

                std::string::size_type lastPos = 0;
                const auto length = line.length(); 
                std::vector<std::string> parts;

                // tokenize first line
                while (lastPos < length + 1)
                {
                    auto pos = line.find(' ', lastPos);
                    if (pos == std::string::npos) pos = length;

                    if (pos != lastPos)
                        parts.emplace_back(line.data() + lastPos,
                                           static_cast<std::vector<std::string>::size_type>(pos) - lastPos);

                    lastPos = pos + 1;
                }

                NS_LOG_FUNCTION(this << parts[0] << parts[1] << parts[2]);

                if (parts.size() >= 2){
                  if(parts[0] == "HTTP/1.1"){
                    m_status = std::stoi(parts[1]);
                  }else{
                    SetMethod( parts[0] );
                    m_uri = parts[1];
                  }
                }
            }
            else // headers
            {
                m_headers.push_back(line);
                m_headerSize += line.size() + 1;

                const auto pos = line.find(':'); 

                if (pos != std::string::npos)
                {
                    std::string headerName = line.substr(0, pos);
                    std::string headerValue = line.substr(pos + 1);

                    // ltrim
                    headerValue.erase(headerValue.begin(),
                                      std::find_if(headerValue.begin(), headerValue.end(),
                                                   [](int c) {return !std::isspace(c);}));

                    // rtrim
                    headerValue.erase(std::find_if(headerValue.rbegin(), headerValue.rend(),
                                                   [](int c) {return !std::isspace(c);}).base(),
                                      headerValue.end());

                    if (headerName == "Content-Length")
                    {
                        m_contentLength = std::stoul(headerValue);
                        contentLengthReceived = true;
                        m_allData.reserve(m_contentLength);
                    }
                    else if (headerName == "Request URI")
                    {
                        m_request_uri = headerValue;
                    }
                    else if (headerName == "Transfer-Encoding")
                    {
                        if (headerValue == "chunked")
                            chunkedResponse = true;
                        else
                          NS_FATAL_ERROR ("Unsupported transfer encoding: " + headerValue);
                    }
                    else if (headerName == "Host")
                    {
                      m_uri = headerValue + m_uri;
                      NS_LOG_FUNCTION(this << headerValue);
                    }
                }
            }
        }

    if (parsedHeaders)
    {

        // Content-Length must be ignored if Transfer-Encoding is received
        if (chunkedResponse)
        {
            bool dataReceived = false;
            for (;;)
            {

                NS_LOG_FUNCTION(this <<"expectedChunkSize:" << expectedChunkSize);
                    
                if (expectedChunkSize > 0)
                {
                    const auto toWrite = std::min(expectedChunkSize, responseData.size());
                    m_payload.insert(m_payload.end(), responseData.begin(), responseData.begin() + static_cast<ptrdiff_t>(toWrite));
                    m_allData.insert(m_allData.end(), responseData.begin(), responseData.begin() + static_cast<ptrdiff_t>(toWrite));
                    responseData.erase(responseData.begin(), responseData.begin() + static_cast<ptrdiff_t>(toWrite));
                    expectedChunkSize -= toWrite;


                    if (expectedChunkSize == 0) removeCrlfAfterChunk = true;
                    if (responseData.empty()) break;
                }
                else
                {
                    if (removeCrlfAfterChunk)
                    {
                        if (responseData.size() >= 2)
                        {
                            removeCrlfAfterChunk = false;
                            responseData.erase(responseData.begin(), responseData.begin() + 2);
                        }
                        else break;
                    }

                    const auto i = std::search(responseData.begin(), responseData.end(), std::begin(crlf), std::end(crlf));

                    if (i == responseData.end()) break;

                    const std::string line(responseData.begin(), i);
                    responseData.erase(responseData.begin(), i + 2);

                    expectedChunkSize = std::stoul(line, nullptr, 16);

                    if (expectedChunkSize == 0)
                    {
                        dataReceived = true;
                        break;
                    }
                }
            }
            NS_LOG_FUNCTION(dataReceived);

           // if (dataReceived)  break;
        }
        else
        {

            m_payload.insert(m_payload.end(), responseData.begin(), responseData.end());
            responseData.clear();

            NS_LOG_FUNCTION(this << "m_contentLength:" << m_contentLength);
            NS_LOG_FUNCTION(this << "payload.size(): " << m_payload.size());
 
            if(m_contentLength > m_payload.size()){
                m_fragmented = true;
                NS_LOG_FUNCTION(this <<"Fragmented header received!");
            }else if(m_contentLength < m_payload.size()){
                NS_LOG_FUNCTION(this << "Extract header data from the rest of the payload!");
                std::vector<uint8_t> vec2(m_payload.begin(), m_payload.begin()+m_contentLength);
                m_payload = vec2;
            }else{
                NS_LOG_FUNCTION(this << "Exact header size received!)");
            }


            std::string payload = std::string{m_payload.begin(), m_payload.end()};
            NS_LOG_FUNCTION(this << "287!!!!!!!" << chunkedResponse << contentLengthReceived << payload);

            // got the whole content
            //if (contentLengthReceived && m_allData.size() >= contentLength) break;
            NS_LOG_FUNCTION(contentLengthReceived);
        }
    }
     
    std::string payload = std::string{m_payload.begin(), m_payload.end()};
    NS_LOG_FUNCTION(this << parsedHeaders << payload << "374m_headerSize:" << m_headerSize << "m_contentLength:" << m_contentLength );

}

std::string
HttpHeader::GetHeaderString(){

    NS_LOG_FUNCTION(this << m_headerSize << m_contentLength);
    std::string output;
    output.assign(m_allData.begin(), m_allData.end());

    NS_LOG_FUNCTION(this << output << output.size() << m_allData.size());
    return output;
}

void
HttpHeader::SetHeaderString(std::string input){

    NS_LOG_FUNCTION(this << input << input.size());
    std::vector<uint8_t> vec(input.begin(), input.end());
    m_allData = vec;

    if(m_headers.size() == 0 && m_payload.size() == 0) ParseResponse();
    
    NS_LOG_FUNCTION(this << "\n" << 
      "input.size(): " << input.size() << "\n" << 
      "Header-Length: " << m_headerSize << "\n" <<
      "Content-Length: " << m_contentLength << "\n"
      "Headers.size():" << m_headers.size() << "\n"
    );

    /*
    if(input.size() < (m_headerSize + m_contentLength+m_headers.size()+4)){
        m_fragmented = true;
        NS_LOG_FUNCTION(this << "Fragment received!" << input.size() << m_headerSize + m_contentLength);
    }else if(input.size() > (m_headerSize + m_contentLength)){
        NS_LOG_FUNCTION(this << "Larger header received!");

        std::vector<uint8_t> vec1(m_allData.begin(), m_allData.begin()+m_headerSize); 
        NS_LOG_FUNCTION(this << "headers vec1.size(): " << vec1.size() );

        std::vector<uint8_t> vec2(m_payload.begin(), m_payload.begin()+m_contentLength);
        m_payload = vec2;
        NS_LOG_FUNCTION(this << "payload vec2.size(): " << vec2.size() );

        std::vector<uint8_t> vec3(m_allData.begin(), m_allData.begin()+m_headerSize+m_headers.size()+4+m_contentLength);
        m_allData = vec3;
        NS_LOG_FUNCTION(this << "all vec3.size(): " << vec3.size() );



        std::string headers = std::string{vec1.begin(), vec1.end()};
        NS_LOG_FUNCTION(this << ":::423:::\n" << headers);
 
        std::string payload = std::string{vec2.begin(), vec2.end()};
        NS_LOG_FUNCTION(this << ":::424:::\n" << payload);

        std::string ALL = std::string{vec3.begin(), vec3.end()};
        NS_LOG_FUNCTION(this << ":::425:::\n" << ALL);

        m_fragmented = false;




    }else{
        NS_LOG_FUNCTION(this << "Exact size header received!");
    }*/

}


// static
TypeId
HttpHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::HttpHeader")
    .SetParent<Header> ()
    .AddConstructor<HttpHeader> ()
  ;
  return tid;
}

TypeId
HttpHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

uint32_t
HttpHeader::GetSerializedSize () const
{
  return (m_headerSize + m_contentLength) * sizeof(uint8_t);
}

void
HttpHeader::Serialize (Buffer::Iterator start) const
{
  NS_LOG_FUNCTION (this << &start);

  NS_LOG_FUNCTION( this 
    << "m_contentLength: " << m_contentLength 
  );

  start.WriteU32 (m_contentLength);

  char tmpBuffer [ m_contentLength ];
  std::copy(m_allData.begin(), m_allData.end(), tmpBuffer);
  start.Write ((uint8_t *)tmpBuffer, m_contentLength);

}

uint32_t
HttpHeader::Deserialize (Buffer::Iterator start)
{
  NS_LOG_FUNCTION ( this << &start << start.GetSize() );
  Buffer::Iterator i = start; 

  m_contentLength = i.ReadU32 ();
  NS_LOG_FUNCTION(this << "m_contentLength: " << m_contentLength);
  NS_LOG_FUNCTION(this << "start.GetSize(): " << start.GetSize());
  NS_LOG_FUNCTION(this << "i.GetDistanceFrom (start) " << i.GetDistanceFrom (start) );

  if(m_contentLength > start.GetSize()){
    return i.GetDistanceFrom (start);    
  }

  //if we have not received the full header
  //i.e start.GetSize() = 1339
  //but we received 4 bytes (i.ReadU32 ()) + m_contentLength (1337)
  //we need two more bytes to receive!
  if(start.GetSize() < i.GetDistanceFrom (start) + m_contentLength){
    return i.GetDistanceFrom (start);    
  }

  char tmpBuffer [ m_contentLength ];
  i.Read ((uint8_t*)tmpBuffer, m_contentLength);

  std::vector<uint8_t> receivedData(tmpBuffer, tmpBuffer + m_contentLength / sizeof(char));
  m_allData = receivedData; 

  uint32_t dist = i.GetDistanceFrom (start);
  NS_LOG_FUNCTION( this << dist << GetSerializedSize() );
  NS_ASSERT (dist == GetSerializedSize ());

  if(m_headers.size() == 0 && m_payload.size() == 0){
    ParseResponse();
  }
  return dist;
}

void
HttpHeader::Print (std::ostream &os) const
{
  NS_LOG_FUNCTION (this << &os);
  os << 
  "Header-Length: " << m_headerSize << "\n" <<
  "Content-Length: " << m_contentLength << "\n" <<
  std::string{m_allData.begin(), m_allData.end()} << "\n";
}

std::string
HttpHeader::ToString () const
{
  NS_LOG_FUNCTION (this);
  std::ostringstream oss;
  Print (oss);
  return oss.str ();
}

uint32_t 
HttpHeader::GetHeaderSize(){
    return m_headerSize;
}

uint32_t
HttpHeader::GetContentSize(){
    NS_LOG_FUNCTION(this);
    return m_contentLength;
}

uint32_t
HttpHeader::GetSize () const
{
  return m_headerSize + m_contentLength;
}

void
HttpHeader::SetStatus (HttpHeader::HttpStatus status)
{
  NS_LOG_FUNCTION (this << status);
   switch (status)
   {
      case Continue: 
            m_status = 100;
            break;
      case SwitchingProtocol: 
            m_status = 101;
            break;
      case Processing: 
            m_status = 102;
            break;
      case EarlyHints: 
            m_status = 103;
            break;

      case Ok: 
            m_status = 200;
            break;
      case Created: 
            m_status = 201;
            break;
      case Accepted: 
            m_status = 202;
            break;
      case NonAuthoritativeInformation: 
            m_status = 203;
            break;
      case NoContent: 
            m_status = 204;
            break;
      case ResetContent: 
            m_status = 205;
            break;
      case PartialContent: 
            m_status = 206;
            break;
      case MultiStatus: 
            m_status = 207;
            break;
      case AlreadyReported: 
            m_status = 208;
            break;
      case ImUsed: 
            m_status = 226;
            break;

      case MultipleChoice: 
            m_status = 300;
            break;
      case MovedPermanently: 
            m_status = 301;
            break;
      case Found: 
            m_status = 302;
            break;
      case SeeOther: 
            m_status = 303;
            break;
      case NotModified: 
            m_status = 304;
            break;
      case UseProxy: 
            m_status = 305;
            break;
      case TemporaryRedirect: 
            m_status = 307;
            break;
      case PermanentRedirect: 
            m_status = 308;
            break;

      case BadRequest: 
            m_status = 400;
            break;
      case Unauthorized: 
            m_status = 401;
            break;
      case PaymentRequired: 
            m_status = 402;
            break;
      case Forbidden: 
            m_status = 403;
            break;
      case NotFound: 
            m_status = 404;
            break;
      case MethodNotAllowed: 
            m_status = 405;
            break;
      case NotAcceptable: 
            m_status = 406;
            break;
      case ProxyAuthenticationRequired: 
            m_status = 407;
            break;
      case RequestTimeout: 
            m_status = 408;
            break;
      case Conflict: 
            m_status = 409;
            break;
      case Gone: 
            m_status = 410;
            break;
      case LengthRequired: 
            m_status = 411;
            break;
      case PreconditionFailed: 
            m_status = 412;
            break;
      case PayloadTooLarge: 
            m_status = 413;
            break;
      case UriTooLong: 
            m_status = 414;
            break;
      case UnsupportedMediaType: 
            m_status = 415;
            break;
      case RangeNotSatisfiable: 
            m_status = 416;
            break;
      case ExpectationFailed: 
            m_status = 417;
            break;
      case ImaTeapot: 
            m_status = 418;
            break;
      case MisdirectedRequest: 
            m_status = 421;
            break;
      case UnprocessableEntity: 
            m_status = 422;
            break;
      case Locked: 
            m_status = 423;
            break;
      case FailedDependency: 
            m_status = 424;
            break;
      case TooEarly: 
            m_status = 425;
            break;
      case UpgradeRequired: 
            m_status = 426;
            break;
      case PreconditionRequired: 
            m_status = 428;
            break;
      case TooManyRequests: 
            m_status = 429;
            break;
      case RequestHeaderFieldsTooLarge: 
            m_status = 431;
            break;
      case UnavailableForLegalReasons: 
            m_status = 451;
            break;

      case InternalServerError: 
            m_status = 500;
            break;
      case NotImplemented: 
            m_status = 501;
            break;
      case BadGateway: 
            m_status = 502;
            break;
      case ServiceUnavailable: 
            m_status = 503;
            break;
      case GatewayTimeout: 
            m_status = 504;
            break;
      case HttpVersionNotSupported: 
            m_status = 505;
            break;
      case VariantAlsoNegotiates: 
            m_status = 506;
            break;
      case InsufficientStorage: 
            m_status = 507;
            break;
      case LoopDetected: 
            m_status = 508;
            break;
      case NotExtended: 
            m_status = 510;
            break;
      case NetworkAuthenticationRequired: 
            m_status = 511;
            break;
      default:
            NS_FATAL_ERROR ("Unknown status: " << m_status);
            break;
      }
}

HttpHeader::HttpStatus
HttpHeader::GetStatus () const
{ 
  HttpStatus ret;
  switch (m_status)
  {
    case 100:
          ret = Continue; 
          break;
    case 101:
          ret = SwitchingProtocol; 
          break;
    case 102:
          ret = Processing; 
          break;
    case 103:
          ret = EarlyHints; 
          break;

    case 200:
          ret = Ok; 
          break;
     case 201:
          ret = Created;
          break;
    case 202:
          ret = Accepted; 
          break;
    case 203:
          ret = NonAuthoritativeInformation; 
          break;
    case 204:
          ret = NoContent; 
          break;
    case 205:
          ret = ResetContent; 
          break;
    case 206:
          ret = PartialContent; 
          break;
    case 207:
          ret = MultiStatus; 
          break;
    case 208:
          ret = AlreadyReported; 
          break;
    case 226:
          ret = ImUsed; 
          break;

    case 300:
          ret = MultipleChoice; 
          break;
    case 301:
          ret = MovedPermanently; 
          break;
    case 302:
          ret = Found; 
          break;
    case 303:
          ret = SeeOther; 
          break;
    case 304:
          ret = NotModified; 
          break;
    case 305:
          ret = UseProxy; 
          break;
    case 307:
          ret = TemporaryRedirect; 
          break;
    case 308:
          ret = PermanentRedirect; 
          break;

    case 400:
          ret = BadRequest; 
          break;
    case 401:
          ret = Unauthorized; 
          break;
    case 402:
          ret = PaymentRequired; 
          break;
    case 403:
          ret = Forbidden; 
          break;
    case 404:
          ret = NotFound; 
          break;
    case 405:
          ret = MethodNotAllowed; 
          break;
    case 406:
          ret = NotAcceptable; 
          break;
    case 407:
          ret = ProxyAuthenticationRequired; 
          break;
    case 408:
          ret = RequestTimeout;
          break;
    case 409:
          ret = Conflict; 
          break;
    case 410:
          ret = Gone; 
          break;
    case 411:
          ret = LengthRequired; 
          break;
    case 412:
          ret = PreconditionFailed; 
          break;
    case 413:
          ret = PayloadTooLarge; 
          break;
    case 414:
          ret = UriTooLong; 
          break;
    case 415:
          ret = UnsupportedMediaType; 
          break;
    case 416:
          ret = RangeNotSatisfiable; 
          break;
    case 417:
          ret = ExpectationFailed; 
          break;
    case 418:
          ret = ImaTeapot; 
          break;
    case 421:
          ret = MisdirectedRequest; 
          break;
    case 422:
          ret = UnprocessableEntity; 
          break;
    case 423:
          ret = Locked; 
          break;
    case 424:
          ret = FailedDependency; 
          break;
    case 425:
          ret = TooEarly; 
          break;
    case 426:
          ret = UpgradeRequired; 
          break;
    case 428: 
          ret = PreconditionRequired; 
          break;
    case 429: 
          ret = TooManyRequests; 
          break;
    case 431:
          ret = RequestHeaderFieldsTooLarge; 
          break;
    case 451:
          ret = UnavailableForLegalReasons; 
          break;

    case 500:
          ret = InternalServerError; 
          break;
    case 501:
          ret = NotImplemented; 
          break;
    case 502:
          ret = BadGateway; 
          break;
    case 503:
          ret = ServiceUnavailable; 
          break;
    case 504:
          ret = GatewayTimeout; 
          break;
    case 505:
          ret = HttpVersionNotSupported; 
          break;
    case 506:
          ret = VariantAlsoNegotiates; 
          break;
    case 507: 
          ret = InsufficientStorage; 
          break;
    case 508:
          ret = LoopDetected; 
          break;
    case 510:
          ret = NotExtended; 
          break;
    case 511:
          ret = NetworkAuthenticationRequired;
          break;
    default:
      NS_FATAL_ERROR ("Unknown status: " << m_status);
      break;
  }
  return ret;
}


std::string
HttpHeader::GetStatusString () const
{ 
  std::string output;
  switch (m_status)
  {
    case 100:
          return "Continue";
    case 101:
          return "SwitchingProtocol";
    case 102:
          return "Processing";
    case 103:
          return "EarlyHints";

    case 200:
          return "Ok";
     case 201:
          return "Created";
    case 202:
          return "Accepted";
    case 203:
          return "NonAuthoritativeInformation";
    case 204:
          return "NoContent";
    case 205:
          return "ResetContent";
    case 206:
          return "PartialContent";
    case 207:
          return "MultiStatus";
    case 208:
          return "AlreadyReported";
    case 226:
          return "ImUsed";

    case 300:
          return "MultipleChoice";
    case 301:
          return "MovedPermanently";
    case 302:
          return "Found";
    case 303:
          return "SeeOther";
    case 304:
          return "NotModified";
    case 305:
          return "UseProxy";
    case 307:
          return "TemporaryRedirect";
    case 308:
          return "PermanentRedirect";

    case 400:
          return "BadRequest";
    case 401:
          return "Unauthorized";
    case 402:
          return "PaymentRequired";
    case 403:
          return "Forbidden";
    case 404:
          return "NotFound";
    case 405:
          return "MethodNotAllowed";
    case 406:
          return "NotAcceptable";
    case 407:
          return "ProxyAuthenticationRequired";
    case 408:
          return "RequestTimeout";
    case 409:
          return "Conflict";
    case 410:
          return "Gone";
    case 411:
          return "LengthRequired";
    case 412:
          return "PreconditionFailed";
    case 413:
          return "PayloadTooLarge";
    case 414:
          return "UriTooLong";
    case 415:
          return "UnsupportedMediaType";
    case 416:
          return "RangeNotSatisfiable";
    case 417:
          return "ExpectationFailed";
    case 418:
          return "ImaTeapot";
    case 421:
          return "MisdirectedRequest";
    case 422:
          return "UnprocessableEntity";
    case 423:
          return "Locked";
    case 424:
          return "FailedDependency";
    case 425:
          return "TooEarly";
    case 426:
          return "UpgradeRequired";
    case 428: 
          return "PreconditionRequired";
    case 429: 
          return "TooManyRequests";
    case 431:
          return "RequestHeaderFieldsTooLarge";
    case 451:
          return "UnavailableForLegalReasons";

    case 500:
          return "InternalServerError";
    case 501:
          return "NotImplemented";
    case 502:
          return "BadGateway";
    case 503:
          return "ServiceUnavailable";
    case 504:
          return "GatewayTimeout";
    case 505:
          return "HttpVersionNotSupported";
    case 506:
          return "VariantAlsoNegotiates";
    case 507: 
          return "InsufficientStorage";
    case 508:
          return "LoopDetected";
    case 510:
          return "NotExtended";
    case 511:
          return "NetworkAuthenticationRequired";
    default:
      NS_FATAL_ERROR ("Unknown status: " << m_status);
      break;
  }
  return output;
}


void 
HttpHeader::SetMethod (const std::string& m){
   
  NS_LOG_FUNCTION (this << m);
  HttpHeader::HttpMethod method;

  if (m == "DELETE")
      method = HttpHeader::DELETE;
  else if (m == "GET")
      method = HttpHeader::GET;
  else if (m == "HEAD")
      method = HttpHeader::HEAD;
  else if (m == "PATCH")
      method = HttpHeader::PATCH;
  else if (m == "POST")
      method = HttpHeader::POST;
  else if (m == "PUT")
      method = HttpHeader::PUT;
  else
      NS_FATAL_ERROR ("Unknown Content-Type: " << m);
  
  SetMethod(method);
}


void 
HttpHeader::SetMethod (HttpHeader::HttpMethod method){
   
  NS_LOG_FUNCTION (this << static_cast<uint16_t> (m_method));

  switch (method)
    {
    case DELETE:
      m_method = 0;
      break;
    case GET:
      m_method = 1;
      break;
    case HEAD:
      m_method = 2;
      break;
    case PATCH:
      m_method = 3;
      break;
    case POST:
      m_method = 4;
      break;
    case PUT:
      m_method = 5;
      break; 
    default:
      NS_FATAL_ERROR ("Unknown Content-Type: " << m_method);
      break;
    }
}
 
HttpHeader::HttpMethod 
HttpHeader::GetMethod () const
{

  HttpMethod ret;
  switch (m_method)
    {
    case 0:
      ret = DELETE;
      break;
    case 1:
      ret = GET;
      break;
    case 2:
      ret = HEAD;
      break;
    case 3:
      ret = PATCH;
      break;
    case 4:
      ret = POST;
      break;
    case 5:
      ret = PUT;
      break; 
      NS_FATAL_ERROR ("Unknown Method: " << m_method);
      break;
    }
  return ret;

}

std::string 
HttpHeader::urlEncode(const std::string& str)
{
    constexpr char hexChars[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    std::string result;

    for (auto i = str.begin(); i != str.end(); ++i)
    {
        const std::uint8_t cp = *i & 0xFF;

        if ((cp >= 0x30 && cp <= 0x39) || // 0-9
            (cp >= 0x41 && cp <= 0x5A) || // A-Z
            (cp >= 0x61 && cp <= 0x7A) || // a-z
            cp == 0x2D || cp == 0x2E || cp == 0x5F) // - . _
            result += static_cast<char>(cp);
        else if (cp <= 0x7F) // length = 1
            result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
        else if ((cp >> 5) == 0x06) // length = 2
        {
            result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
            if (++i == str.end()) break;
            result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
        }
        else if ((cp >> 4) == 0x0E) // length = 3
        {
            result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
            if (++i == str.end()) break;
            result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
            if (++i == str.end()) break;
            result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
        }
        else if ((cp >> 3) == 0x1E) // length = 4
        {
            result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
            if (++i == str.end()) break;
            result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
            if (++i == str.end()) break;
            result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
            if (++i == str.end()) break;
            result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
        }
    }

    return result;
} 

std::string
HttpHeader::GetUri() const
{
  return m_uri;
}

std::string 
HttpHeader::GetRequestUri() const{
    return m_request_uri;
}

void
HttpHeader::SetUri(const std::string& url)
{
  NS_LOG_FUNCTION (this << url << url.length() ); 

  m_uri = url;

  const auto schemeEndPosition = url.find("://");

  if (schemeEndPosition != std::string::npos)
  {
      m_scheme = url.substr(0, schemeEndPosition);
      m_path = url.substr(schemeEndPosition + 3);
  }
  else
  {
      m_scheme = "http";
      m_path = url;
  }

  const auto fragmentPosition = m_path.find('#');

  // remove the fragment part
  if (fragmentPosition != std::string::npos)
      m_path.resize(fragmentPosition);

  const auto pathPosition = m_path.find('/');

  if (pathPosition == std::string::npos)
  {
      m_domain = m_path;
      m_path = "/";
  }
  else
  {
      m_domain = m_path.substr(0, pathPosition);
      m_path = m_path.substr(pathPosition);
  }

  const auto portPosition = m_domain.find(':');

  if (portPosition != std::string::npos)
  { 
      m_domain.resize(portPosition);
  }

  NS_LOG_FUNCTION(this << m_domain << m_path << m_scheme);

}
 
} // namespace ns3
