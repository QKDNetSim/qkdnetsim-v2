/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2020 DOTFEESA www.tk.etf.unsa.ba
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
 * Author:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *          Miralem Mehic <miralem.mehic@ieee.org>
 */

#ifndef HTTP_HEADER_H
#define HTTP_HEADER_H

#include <ns3/header.h>
#include <ns3/nstime.h>
#include <string>
#include <algorithm> 

namespace ns3 {

class Packet;

/**
 * \ingroup http
 * \brief Header used by web browsing applications to transmit information about
 *        content type, content length and timestamps for delay statistics.
 *
 * The header contains the following fields (and their respective size when
 * serialized):
 *   - content type (2 bytes);
 *   - content length (4 bytes);
 *   - client time stamp (8 bytes); and
 *   - server time stamp (8 bytes).
 *
 * The header is attached to every packet transmitted by HttpClient and
 * HttpServer applications. In received, split packets, only the first packet
 * of transmitted object contains the header, which helps to identify how many bytes are
 * left to be received.
 *
 * The last 2 fields allow the applications to compute the propagation delay of
 * each packet. The *client TS* field indicates the time when the request
 * packet is sent by the HttpClient, while the *server TS* field indicates the
 * time when the response packet is sent by the HttpServer.
 */
class HttpHeader : public Header
{
public:


  /// The possible types of content (default = NOT_SET).
  enum ContentType_t
  {
    NOT_SET = 0,         ///< Integer equivalent = 0.
    MAIN_OBJECT = 1,     ///< Integer equivalent = 1.
    EMBEDDED_OBJECT = 2  ///< Integer equivalent = 2.
  };

  enum HttpMethod {
      DELETE = 0, /**< Http Method Delete */
      GET = 1, /**< Http Method GET */
      HEAD = 2, /**< Http Method Head */
      PATCH = 3, /**< Http Method Patch */
      POST = 4, /**< Http Method Post */
      PUT = 5 /**< Http Method Put */
  };

  enum HttpStatus
  {
      Continue = 100,
      SwitchingProtocol = 101,
      Processing = 102,
      EarlyHints = 103,

      Ok = 200,
      Created = 201,
      Accepted = 202,
      NonAuthoritativeInformation = 203,
      NoContent = 204,
      ResetContent = 205,
      PartialContent = 206,
      MultiStatus = 207,
      AlreadyReported = 208,
      ImUsed = 226,

      MultipleChoice = 300,
      MovedPermanently = 301,
      Found = 302,
      SeeOther = 303,
      NotModified = 304,
      UseProxy = 305,
      TemporaryRedirect = 307,
      PermanentRedirect = 308,

      BadRequest = 400,
      Unauthorized = 401,
      PaymentRequired = 402,
      Forbidden = 403,
      NotFound = 404,
      MethodNotAllowed = 405,
      NotAcceptable = 406,
      ProxyAuthenticationRequired = 407,
      RequestTimeout = 408,
      Conflict = 409,
      Gone = 410,
      LengthRequired = 411,
      PreconditionFailed = 412,
      PayloadTooLarge = 413,
      UriTooLong = 414,
      UnsupportedMediaType = 415,
      RangeNotSatisfiable = 416,
      ExpectationFailed = 417,
      ImaTeapot = 418,
      MisdirectedRequest = 421,
      UnprocessableEntity = 422,
      Locked = 423,
      FailedDependency = 424,
      TooEarly = 425,
      UpgradeRequired = 426,
      PreconditionRequired = 428,
      TooManyRequests = 429,
      RequestHeaderFieldsTooLarge = 431,
      UnavailableForLegalReasons = 451,

      InternalServerError = 500,
      NotImplemented = 501,
      BadGateway = 502,
      ServiceUnavailable = 503,
      GatewayTimeout = 504,
      HttpVersionNotSupported = 505,
      VariantAlsoNegotiates = 506,
      InsufficientStorage = 507,
      LoopDetected = 508,
      NotExtended = 510,
      NetworkAuthenticationRequired = 511
  }; 

  /// Creates an empty instance	.
  HttpHeader ();

  void CreateRequest(
    const std::string& url,
    const std::string& method,
    const std::map<std::string, std::string>& parameters,
    const std::vector<std::string>& headers = {}
  );

  void CreateRequest(
    const std::string& url,
    const std::string& method = "GET",
    const std::string& body = "",
    const std::vector<std::string>& headers = {}
  );

  void CreateRequest(
    const std::string& url,
    const std::string& method,
    const std::vector<uint8_t>& body,
    const std::vector<std::string>& headers
  );

  void CreateResponse(
    const HttpHeader::HttpStatus status,
    const std::map<std::string, std::string>& body,
    const std::vector<std::string>& headers = {}
  );

  void CreateResponse(
    const HttpHeader::HttpStatus status,
    const std::string& body = "",
    const std::vector<std::string>& headers = {}
  );

  void CreateResponse(
    const HttpHeader::HttpStatus status,
    const std::vector<uint8_t>& body,
    const std::vector<std::string>& headers
  );

  /**
   * Returns the object TypeId.
   * \return The object TypeId.
   */
  static TypeId GetTypeId ();

  // Inherited from ObjectBase base class.
  virtual TypeId GetInstanceTypeId () const;

  // Inherited from Header base class.
  virtual uint32_t GetSerializedSize () const;
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);
  virtual void Print (std::ostream &os) const;

  /**
   * \return The string representation of the header.
   */
  std::string ToString () const;

  std::vector<uint8_t> GetPayload(){
    return m_payload;
  }

  std::string GetPayloadString(){
    if(m_headers.size() == 0 && m_payload.size() == 0) ParseResponse();
    std::string payload = std::string{m_payload.begin(), m_payload.end()};
    return payload;
  }

  /**
   * \return The content length (in bytes).
   */
  uint32_t GetSize () const;

  /**
   * \param status The connection status.
   */
  void SetStatus (HttpStatus status);

  /**
   * \return The connection status.
   */
  HttpStatus GetStatus () const;

  std::string GetStatusString () const;

  /**
   * \param method The connection method.
   */
  void SetMethod (HttpMethod method);

  void SetMethod (const std::string& m);

  /**
   * \return The connection method.
   */
  HttpMethod GetMethod () const;

  /**
   * \return The uri value
   */
  std::string GetUri() const;
  /**
   * \param std::string The uri.
   */
  void SetUri(const std::string& url);

  /**
   * \return The request uri value
   */
  std::string GetRequestUri() const; 

  std::string urlEncode(const std::string& str);

  void ParseResponse();

  std::string GetHeaderString();

  void SetHeaderString(std::string input); 

  uint32_t GetContentSize();

  uint32_t GetHeaderSize();

  bool IsFragmented(){
    return m_fragmented;
  }

private:

  std::string m_scheme;
  std::string m_domain; 
  std::string m_path;

  std::vector<std::string> m_headers;
  std::vector<uint8_t> m_payload; 
  std::vector<uint8_t> m_allData; //headers + emptyLine + m_payload
  
  uint16_t m_method;        //!<" Connection method field in integer format.
  uint16_t m_status;        //!<" Connection status field in integer format.
  uint16_t m_contentType;   //!<" Content type field in integer format.
  uint32_t m_contentLength; //!<" Content length field (in bytes unit).
  uint32_t m_headerSize;

  bool     m_fragmented;

  std::string m_uri; 
  std::string m_request_uri;  

}; // end of `class HttpHeader`


} // end of `namespace ns3`


#endif /* HTTP_HEADER_H */
