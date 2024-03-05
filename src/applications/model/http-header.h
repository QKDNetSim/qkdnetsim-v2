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
  /// Creates an empty instance	.
  HttpHeader ();

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

  /**
   * \param contentType The content type.
   */
  void SetContentType (ContentType_t contentType);

  /**
   * \return The content type.
   */
  ContentType_t GetContentType () const;

  /**
   * \param contentLength The content length (in bytes).
   */
  void SetContentLength (uint32_t contentLength);

  /**
   * \return The content length (in bytes).
   */
  uint32_t GetContentLength () const;

  /**
   * \param status The connection status.
   */
  void SetStatus (HttpStatus status);

  /**
   * \return The connection status.
   */
  HttpStatus GetStatus () const;

  /**
   * \param method The connection method.
   */
  void SetMethod (HttpMethod method);

  /**
   * \return The connection method.
   */
  HttpMethod GetMethod () const;

  /**
   * \param std::string The uri.
   */
  void SetUri (std::string uri);

  /**
   * \return The the uri.
   */
  std::string GetUri () const;

  /**
   * \brief Set the size information that the header will carry
   * \param size the size
   */
  void SetSize (uint64_t size);

  /**
   * \brief Get the size information that the header is carrying
   * \return the size
   */
  uint64_t GetSize (void) const;

private:
  uint16_t m_method;        //!<" Connection method field in integer format.
  uint16_t m_status;        //!<" Connection status field in integer format.
  uint16_t m_contentType;   //!<" Content type field in integer format.
  uint32_t m_contentLength; //!<" Content length field (in bytes unit).
  uint64_t m_size {0};      //!< The 'size' information that the header is carrying
  std::string m_uri;
  std::vector <std::string> uriParams;

}; // end of `class HttpHeader`


} // end of `namespace ns3`


#endif /* HTTP_HEADER_H */
