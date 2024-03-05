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
#include "http-header.h"

NS_LOG_COMPONENT_DEFINE ("HttpHeader");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (HttpHeader);

HttpHeader::HttpHeader ()
  : Header (),
  m_status(0),
  m_contentType (MAIN_OBJECT),
  m_contentLength (0)
{
  NS_LOG_FUNCTION (this);
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
  return 3 * sizeof(uint16_t) + 
  sizeof(uint32_t) + 
  sizeof(uint64_t) + 
  m_contentLength * sizeof(char);
}

void
HttpHeader::Serialize (Buffer::Iterator start) const
{
  NS_LOG_FUNCTION (this << &start);

  start.WriteU16 (m_method);
  start.WriteU16 (m_status);
  start.WriteU16 (m_contentType);
  start.WriteU32 (m_contentLength);
  start.WriteU64 (m_size);

  NS_LOG_FUNCTION(this << "m_method: " << m_method);
  NS_LOG_FUNCTION(this << "m_status: " << m_status);
  NS_LOG_FUNCTION(this << "m_contentType: " << m_contentType);
  NS_LOG_FUNCTION(this << "m_contentLength: " << m_contentLength);
  NS_LOG_FUNCTION(this << "m_size: " << m_size);

  char tmpBuffer [m_contentLength];
  strcpy (tmpBuffer, m_uri.c_str());
  start.Write ((uint8_t *)tmpBuffer, m_contentLength );
}

uint32_t
HttpHeader::Deserialize (Buffer::Iterator start)
{
  NS_LOG_FUNCTION (this << &start);
  Buffer::Iterator i = start; 

  m_method        = i.ReadU16 (); 
  m_status        = i.ReadU16 (); 
  m_contentType   = i.ReadU16 (); 
  m_contentLength = i.ReadU32 ();
  m_size          = i.ReadU64 ();

  NS_LOG_FUNCTION(this << "m_method: " << m_method);
  NS_LOG_FUNCTION(this << "m_status: " << m_status);
  NS_LOG_FUNCTION(this << "m_contentType: " << m_contentType);
  NS_LOG_FUNCTION(this << "m_contentLength: " << m_contentLength);
  NS_LOG_FUNCTION(this << "m_size: " << m_size);

  char tmpBuffer [m_contentLength];
  i.Read ((uint8_t*)tmpBuffer, m_contentLength);
  m_uri = std::string(tmpBuffer).substr(0, m_contentLength);  

  NS_LOG_FUNCTION(this << m_uri << m_uri.length() << m_contentLength );

  uint32_t dist = i.GetDistanceFrom (start);
  NS_LOG_FUNCTION( this << dist << GetSerializedSize() );
  NS_ASSERT (dist == GetSerializedSize ());
  return dist;
}

void
HttpHeader::Print (std::ostream &os) const
{
  NS_LOG_FUNCTION (this << &os);
  os << "(Method: " << m_method
     << " Status: " << m_status
     << " Content-Type: " << m_contentType
     << " Content-Length: " << m_contentLength 
     << " URI: " << m_uri << ")";
}

std::string
HttpHeader::ToString () const
{
  NS_LOG_FUNCTION (this);
  std::ostringstream oss;
  Print (oss);
  return oss.str ();
}
 
void
HttpHeader::SetContentType (HttpHeader::ContentType_t contentType)
{
  NS_LOG_FUNCTION (this << static_cast<uint16_t> (contentType));
  switch (contentType)
    {
    case NOT_SET:
      m_contentType = 0;
      break;
    case MAIN_OBJECT:
      m_contentType = 1;
      break;
    case EMBEDDED_OBJECT:
      m_contentType = 2;
      break;
    default:
      NS_FATAL_ERROR ("Unknown Content-Type: " << contentType);
      break;
    }
}

HttpHeader::ContentType_t
HttpHeader::GetContentType () const
{
  ContentType_t ret;
  switch (m_contentType)
    {
    case 0:
      ret = NOT_SET;
      break;
    case 1:
      ret = MAIN_OBJECT;
      break;
    case 2:
      ret = EMBEDDED_OBJECT;
      break;
    default:
      NS_FATAL_ERROR ("Unknown Content-Type: " << m_contentType);
      break;
    }
  return ret;
}

void
HttpHeader::SetContentLength (uint32_t contentLength)
{
  NS_LOG_FUNCTION (this << contentLength);
  m_contentLength = contentLength;
}


uint32_t
HttpHeader::GetContentLength () const
{
  return m_contentLength;
}


void
HttpHeader::SetSize (uint64_t size)
{
  m_size = size;
}

uint64_t
HttpHeader::GetSize (void) const
{
  return m_size;
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
HttpHeader::GetUri() const
{
  return m_uri;
}
 
void
HttpHeader::SetUri(std::string uri)
{
  NS_LOG_FUNCTION (this << uri << m_uri.length() );
  m_uri = uri;
  SetContentLength(m_uri.length());
}
 
} // namespace ns3
