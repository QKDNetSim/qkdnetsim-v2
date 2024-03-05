.. include:: replace.txt
.. highlight:: cpp

++++++++++++++++++++
Design Documentation
++++++++++++++++++++


|ns3| nodes can contain a collection of NetDevice objects, much like an actual
computer contains separate interface cards for Ethernet, Wifi, Bluetooth, etc.
This chapter describes the |ns3| WifiNetDevice and related models. By adding
WifiNetDevice objects to |ns3| nodes, one can create models of 802.11-based
infrastructure and ad hoc networks.

Overview of the model
*********************

The WifiNetDevice models a wireless network interface controller based
on the IEEE 802.11 standard [ieee80211]_. We will go into more detail below but in brief,
|ns3| provides models for these aspects of 802.11:

* basic 802.11 DCF with **infrastructure** and **adhoc** modes
* **802.11a**, **802.11b**, **802.11g**, **802.11n** (both 2.4 and 5 GHz bands), **802.11ac**, **802.11ax** (2.4, 5 and 6 GHz bands) and **802.11be** physical layers
* **MSDU aggregation** and **MPDU aggregation** extensions of 802.11n, and both can be combined together (two-level aggregation)
* 802.11ax **DL OFDMA** and **UL OFDMA** (including support for the MU EDCA Parameter Set)
* 802.11be **Multi-link** discovery and setup
* QoS-based EDCA and queueing extensions of **802.11e**
* the ability to use different propagation loss models and propagation delay models,
  please see the chapter on :ref:`Propagation` for more detail
* packet error models and frame detection models that have been validated
  against link simulations and other references
* various rate control algorithms including **Aarf, Arf, Cara, Onoe, Rraa,
  ConstantRate, Minstrel and Minstrel-HT**
* 802.11s (mesh), described in another chapter
* 802.11p and WAVE (vehicular), described in another chapter

The set of 802.11 models provided in |ns3| attempts to provide an accurate
MAC-level implementation of the 802.11 specification and to provide a
packet-level abstraction of the PHY-level for different PHYs, corresponding to
802.11a/b/e/g/n/ac/ax/be specifications.

In |ns3|, nodes can have multiple WifiNetDevices on separate channels, and the
WifiNetDevice can coexist with other device types.
With the use of the **SpectrumWifiPhy** framework, one can also build scenarios
involving cross-channel interference or multiple wireless technologies on
a single channel.

The source code for the WifiNetDevice and its models lives in the directory
``src/wifi``.

The implementation is modular and provides roughly three sublayers of models:

* the **PHY layer models**: they model amendment-specific and common
  PHY layer operations and functions.
* the so-called **MAC low models**: they model functions such as medium
  access (DCF and EDCA), frame protection (RTS/CTS) and acknowledgment (ACK/BlockAck).
  In |ns3|, the lower-level MAC is comprised of a **Frame Exchange Manager** hierarchy,
  a **Channel Access Manager** and a **MAC middle** entity.
* the so-called **MAC high models**: they implement non-time-critical processes
  in Wifi such as the MAC-level beacon generation, probing, and association
  state machines, and a set of **Rate control algorithms**.  In the literature,
  this sublayer is sometimes called the **upper MAC** and consists of more
  software-oriented implementations vs. time-critical hardware implementations.

Next, we provide a design overview of each layer, shown in
Figure :ref:`wifi-architecture`. For 802.11be Multi-Link Devices (MLDs),
there as many instances of WifiPhy, FrameExchangeManager and ChannelAccessManager
as the number of links.

.. _wifi-architecture:

.. figure:: figures/WifiArchitecture.*

   *WifiNetDevice architecture*

MAC high models
===============

There are presently three **MAC high models** that provide for the three
(non-mesh; the mesh equivalent, which is a sibling of these with common
parent ``ns3::WifiMac``, is not discussed here) Wi-Fi topological
elements - Access Point (AP) (``ns3::ApWifiMac``),
non-AP Station (STA) (``ns3::StaWifiMac``), and STA in an Independent
Basic Service Set (IBSS) - also commonly referred to as an ad hoc
network (``ns3::AdhocWifiMac``).

The simplest of these is ``ns3::AdhocWifiMac``, which implements a
Wi-Fi MAC that does not perform any kind of beacon generation,
probing, or association. The ``ns3::StaWifiMac`` class implements
an active probing and association state machine that handles automatic
re-association whenever too many beacons are missed. Finally,
``ns3::ApWifiMac`` implements an AP that generates periodic
beacons, and that accepts every attempt to associate.

These three MAC high models share a common parent in
``ns3::WifiMac``, which exposes, among other MAC
configuration, an attribute ``QosSupported`` that allows
configuration of 802.11e/WMM-style QoS support.

There are also several **rate control algorithms** that can be used by the
MAC low layer.  A complete list of available rate control algorithms is
provided in a separate section.

MAC low layer
==============

The **MAC low layer** is split into three main components:

#. ``ns3::FrameExchangeManager`` a class hierarchy which implement the frame exchange
   sequences introduced by the supported IEEE 802.11 amendments. It also handles
   frame aggregation, frame retransmissions, protection and acknowledgment.
#. ``ns3::ChannelAccessManager`` which implements the DCF and EDCAF
   functions.
#. ``ns3::Txop`` and ``ns3::QosTxop`` which handle the packet queue.
   The ``ns3::Txop`` object is used by high MACs that are not QoS-enabled,
   and for transmission of frames (e.g., of type Management)
   that the standard says should access the medium using the DCF.
   ``ns3::QosTxop`` is used by QoS-enabled high MACs.

PHY layer models
================

In short, the physical layer models are mainly responsible for modeling
the reception of packets and for tracking energy consumption.  There
are typically three main components to packet reception:

* each packet received is probabilistically evaluated for successful or
  failed reception.  The probability depends on the modulation, on
  the signal to noise (and interference) ratio for the packet, and on
  the state of the physical layer (e.g. reception is not possible while
  transmission or sleeping is taking place);
* an object exists to track (bookkeeping) all received signals so that
  the correct interference power for each packet can be computed when
  a reception decision has to be made; and
* one or more error models corresponding to the modulation and standard
  are used to look up probability of successful reception.

|ns3| offers users a choice between two physical layer models, with a
base interface defined in the ``ns3::WifiPhy`` class.  The YansWifiPhy
class implements a simple physical layer model, which is described
in a paper entitled
`Yet Another Network Simulator <https://dl.acm.org/doi/pdf/10.1145/1190455.1190467?download=true>`_
The acronym *Yans* derives from this paper title.  The SpectrumWifiPhy
class is a more advanced implementation based on the Spectrum framework
used for other |ns3| wireless models.  Spectrum allows a fine-grained
frequency decomposition of the signal, and permits scenarios to
include multiple technologies coexisting on the same channel.

Scope and Limitations
*********************

The IEEE 802.11 standard [ieee80211]_ is a large specification,
and not all aspects are covered by |ns3|; the documentation of |ns3|'s
conformance by itself would lead to a very long document.  This section
attempts to summarize compliance with the standard and with behavior
found in practice.

The physical layer and channel models operate on a per-packet basis, with
no frequency-selective propagation nor interference effects when using
the default YansWifiPhy model.  Directional antennas are also not
supported at this time.  For additive white Gaussian noise (AWGN)
scenarios, or wideband interference scenarios, performance is governed
by the application of analytical models (based on modulation and factors
such as channel width) to the received signal-to-noise ratio, where noise
combines the effect of thermal noise and of interference from other Wi-Fi
packets.  Interference from other wireless technologies is only modeled
when the SpectrumWifiPhy is used.
The following details pertain to the physical layer and channel models:

* 802.11n/ac/ax/be beamforming is not supported
* 802.11n RIFS is not supported
* 802.11 PCF/HCF/HCCA are not implemented
* Channel Switch Announcement is not supported
* Authentication and encryption are missing
* Processing delays are not modeled
* Cases where RTS/CTS and ACK are transmitted using HT/VHT/HE/EHT formats are not supported
* Energy consumption model does not consider MIMO
* 802.11ax preamble puncturing is supported by the PHY but is currently not exploited by the MAC
* Only minimal MU-MIMO is supported (ideal PHY assumed, no MAC layer yet)

At the MAC layer, most of the main functions found in deployed Wi-Fi
equipment for 802.11a/b/e/g/n/ac/ax/be are implemented, but there are scattered instances
where some limitations in the models exist. Support for 802.11n, ac, ax and be is evolving.

Some implementation choices that are not imposed by the standard are listed below:

* BSSBasicRateSet for 802.11b has been assumed to be 1-2 Mbit/s
* BSSBasicRateSet for 802.11a/g has been assumed to be 6-12-24 Mbit/s
* OperationalRateSet is assumed to contain all mandatory rates (see
  `issue 183 <https://gitlab.com/nsnam/ns-3-dev/-/issues/183>`_)
* The wifi manager always selects the lowest basic rate for management frames.
* If a STA (AP or non-AP) supports VHT, a Block Ack agreement is always setup once
  a first packet is enqueued regardless of whether it will be transmitted in an A-MPDU.
* Once an A-MSDU is created, it is no longer modified, even before it is actually transmitted
  for the first time. This means that this A-MSDU cannot be aggregated to other MSDUs using A-MSDU
  aggregation.

Design Details
**************

The remainder of this section is devoted to more in-depth design descriptions
of some of the Wi-Fi models.  Users interested in skipping to the section
on usage of the wifi module (:ref:`User Documentation<sec-wifi-user-doc>`) may do so at this point.
We organize these more detailed sections from the bottom-up, in terms of
layering, by describing the channel and PHY models first, followed by
the MAC models.

We focus first on the choice between physical layer frameworks.  |ns3|
contains support for a Wi-Fi-only physical layer model called YansWifiPhy
that offers no frequency-level decomposition of the signal.  For simulations
that involve only Wi-Fi signals on the Wi-Fi channel, and that do not
involve frequency-dependent propagation loss or fading models, the default
YansWifiPhy framework is a suitable choice.  For simulations involving
mixed technologies on the same channel, or frequency dependent effects,
the SpectrumWifiPhy is more appropriate.  The two frameworks are very
similarly configured.

The SpectrumWifiPhy framework uses the :ref:`sec-spectrum-module` channel
framework.

The YansWifiChannel is the only concrete channel model class in
the |ns3| wifi module.  The
``ns3::YansWifiChannel`` implementation uses the propagation loss and
delay models provided within the |ns3| :ref:`Propagation` module.
In particular, a number of propagation models can be added (chained together,
if multiple loss models are added) to the channel object, and a propagation
delay model also added. Packets sent from a ``ns3::YansWifiPhy`` object
onto the channel with a particular signal power, are copied to all of the
other ``ns3::YansWifiPhy`` objects after the signal power is reduced due
to the propagation loss model(s), and after a delay corresponding to
transmission (serialization) delay and propagation delay due to
any channel propagation delay model (typically due to speed-of-light
delay between the positions of the devices).

Only objects of ``ns3::YansWifiPhy`` may be attached to a
``ns3::YansWifiChannel``; therefore, objects modeling other
(interfering) technologies such as LTE are not allowed. Furthermore,
packets from different channels do not interact; if a channel is logically
configured for e.g. channels 5 and 6, the packets do not cause
adjacent channel interference (even if their channel numbers overlap).

WifiPhy and related models
==========================

The ``ns3::WifiPhy`` is an abstract base class representing the 802.11
physical layer functions.  Packets passed to this object (via a
``Send()`` method) are sent over a channel object, and
upon reception, the receiving PHY object decides (based on signal power
and interference) whether the packet was successful or not.  This class
also provides a number of callbacks for notifications of physical layer
events, exposes a notion of a state machine that can be monitored for
MAC-level processes such as carrier sense, and handles sleep/wake/off models
and energy consumption.  The ``ns3::WifiPhy`` hooks to the ``ns3::FrameExchangeManager``
object in the WifiNetDevice.

There are currently two implementations of the ``WifiPhy``: the
``ns3::YansWifiPhy`` and the ``ns3::SpectrumWifiPhy``.  They each work in
conjunction with five other objects:

* **PhyEntity**: Contains the amendment-specific part of the PHY processing
* **WifiPpdu**: Models the amendment-specific PHY protocol data unit (PPDU)
* **WifiPhyStateHelper**:  Maintains the PHY state machine
* **InterferenceHelper**:  Tracks all packets observed on the channel
* **ErrorModel**:  Computes a probability of error for a given SNR

PhyEntity
##################################

A bit of background
-------------------

Some restructuring of ``ns3::WifiPhy`` and ``ns3::WifiMode`` (among others) was necessary
considering the size and complexity of the corresponding files.
In addition, adding and maintaining new PHY amendments had become a complex
task (especially those implemented inside other modules, e.g. DMG).
The adopted solution was to have ``PhyEntity`` classes that contain the "clause"
specific (i.e. HT/VHT/HE/EHT etc) parts of the PHY process.

The notion of "PHY entity" is in the standard at the beginning of each PHY
layer description clause, e.g. section 21.1.1 of IEEE 802.11-2016:

::
Clause 21 specifies the **PHY entity** for a very high throughput (VHT) orthogonal
frequency division multiplexing (OFDM) system.

*Note that there is already such a name inside the wave module
(e.g. ``WaveNetDevice::AddPhy``) to designate the WifiPhys on each 11p channel,
but the wording is only used within the classes and there is no file using
that name, so no ambiguity in using the name for 802.11 amendments.*

Architecture
-------------------

The abstract base class ``ns3::PhyEntity`` enables to have a unique set of APIs
to be used by each PHY entity, corresponding to the different amendments of
the IEEE 802.11 standard. The currently implemented PHY entities are:

* ``ns3::DsssPhy``: PHY entity for DSSS and HR/DSSS (11b)
* ``ns3::OfdmPhy``: PHY entity for OFDM (11a and 11p)
* ``ns3::ErpOfdmPhy``: PHY entity for ERP-OFDM (11g)
* ``ns3::HtPhy``: PHY entity for HT (11n)
* ``ns3::VhtPhy``: PHY entity for VHT (11ac)
* ``ns3::HePhy``: PHY entity for HE (11ax)
* ``ns3::EhtPhy``: PHY entity for EHT (11be)

Their inheritance diagram is given in Figure :ref:`phyentity-hierarchy` and
closely follows the standard's logic, e.g. section 21.1.1 of IEEE 802.11-2016:

::
The VHT PHY is **based** on the HT PHY defined in Clause 19, which **in turn**
is **based** on the OFDM PHY defined in Clause 17.

.. _phyentity-hierarchy:

.. figure:: figures/PhyEntityHierarchy.*

   *PhyEntity hierarchy*

Such an architecture enables to handle the following operations in an amendment-
specific manner:

* ``WifiMode`` handling and data/PHY rate computation,
* PPDU field size and duration computation, and
* Transmit and receive paths.

WifiPpdu
##################################

In the same vein as ``PhyEntity``, the ``ns3::WifiPpdu`` base class has been
specialized into the following amendment-specific PPDUs:

* ``ns3::DsssPpdu``: PPDU for DSSS and HR/DSSS (11b)
* ``ns3::OfdmPpdu``: PPDU for OFDM (11a and 11p)
* ``ns3::ErpOfdmPpdu``: PPDU for ERP-OFDM (11g)
* ``ns3::HtPpdu``: PPDU for HT (11n)
* ``ns3::VhtPpdu``: PPDU for VHT (11ac)
* ``ns3::HePpdu``: PPDU for HE (11ax)
* ``ns3::EhtPpdu``: PPDU for EHT (11be)

Their inheritance diagram is given in Figure :ref:`wifippdu-hierarchy` and
closely follows the standard's logic, e.g. section 21.3.8.1 of IEEE 802.11-2016:

::
To maintain compatibility with non-VHT STAs, specific non-VHT fields are defined
that can be received by non-VHT STAs compliant with **Clause 17** [OFDM] or **Clause 19** [HT].

.. _wifippdu-hierarchy:

.. figure:: figures/WifiPpduHierarchy.*

   *WifiPpdu hierarchy*

YansWifiPhy and WifiPhyStateHelper
##################################

Class ``ns3::YansWifiPhy`` is responsible for taking packets passed to
it from the MAC (the ``ns3::FrameExchangeManager`` object) and sending them onto the
``ns3::YansWifiChannel`` to which it is attached.  It is also responsible
to receive packets from that channel, and, if reception is deemed to have
been successful, to pass them up to the MAC.

The energy of the signal intended to be received is
calculated from the transmission power and adjusted based on the Tx gain
of the transmitter, Rx gain of the receiver, and any path loss propagation
model in effect.

Class ``ns3::WifiPhyStateHelper`` manages the state machine of the PHY
layer, and allows other objects to hook as *listeners* to monitor PHY
state.  The main use of listeners is for the MAC layer to know when
the PHY is busy or not (for transmission and collision avoidance).

The PHY layer can be in one of these states:

#. TX: the PHY is currently transmitting a signal on behalf of its associated
   MAC
#. RX: the PHY is synchronized on a signal and is waiting until it has received
   its last bit to forward it to the MAC.
#. CCA_BUSY: the PHY is issuing a PHY-CCA.indication(BUSY) indication for the primary channel.
#. IDLE: the PHY is not in the TX, RX, or CCA_BUSY states.
#. SWITCHING: the PHY is switching channels.
#. SLEEP: the PHY is in a power save mode and cannot send nor receive frames.
#. OFF: the PHY is powered off and cannot send nor receive frames.

Packet reception works as follows.  For ``YansWifiPhy``, most of the logic
is implemented in the ``WifiPhy`` base class.  The ``YansWifiChannel`` calls
``WifiPhy::StartReceivePreamble ()``. The latter calls
``PhyEntity::StartReceivePreamble ()`` of the appropriate PHY entity
to start packet reception, but first
there is a check of the packet's notional signal power level against a
threshold value stored in the attribute ``WifiPhy::RxSensitivity``.  Any
packet with a power lower than RxSensitivity will be dropped with no
further processing.  The default value is -101 dBm, which is the thermal
noise floor for 20 MHz signal at room temperature.  The purpose of this
attribute is two-fold:  1) very weak signals that will not affect the
outcome will otherwise consume simulation memory and event processing, so
they are discarded, and 2) this value can be adjusted upwards to function as
a basic carrier sense threshold limitation for experiments involving
spatial reuse considerations.  Users are cautioned about the behavior of
raising this threshold; namely, that all packets with power below this
threshold will be discarded upon reception.

In ``StartReceivePreamble ()``, the packet is immediately added
to the interference helper for signal-to-noise
tracking, and then further reception steps are decided upon the state of
the PHY.  In the case that the PHY is transmitting, for instance, the
packet will be dropped.  If the PHY is IDLE, or if the PHY is receiving and
an optional FrameCaptureModel is being used (and the packet is within
the capture window), then ``PhyEntity::StartPreambleDetectionPeriod ()`` is called next.

The ``PhyEntity::StartPreambleDetectionPeriod ()`` will typically schedule an event,
``PhyEntity::EndPreambleDetectionPeriod ()``, to occur at
the notional end of the first OFDM symbol, to check whether the preamble
has been detected.  As of revisions to the model in ns-3.30, any state
machine transitions from IDLE state are suppressed until after the preamble
detection event.

The ``PhyEntity::EndPreambleDetectionPeriod ()`` method will check, with a preamble detection
model, whether the signal is strong enough to be received, and if so,
an event ``PhyEntity::EndReceiveField ()`` is scheduled for the end of the
preamble and the PHY is put into the CCA_BUSY state. Currently, there is only a
simple threshold-based preamble detection model in ns-3,
called ``ThresholdPreambleDetectionModel``.  If there is no preamble detection
model, the preamble is assumed to have been detected.
It is important to note that, starting with the ns-3.30 release, the default
in the WifiPhyHelper is to add the ``ThresholdPreambleDetectionModel`` with
a threshold RSSI of -82 dBm, and a threshold SNR of 4 dB.  Both the RSSI
and SNR must be above these respective values for the preamble to be
successfully detected.  The default sensitivity has been reduced in ns-3.30
compared with that of previous releases, so some packet receptions that were
previously successful will now fail on this check.  More details on the
modeling behind this change are provided in [lanante2019]_.

The ``PhyEntity::EndReceiveField ()`` method will check the correct reception
of the current preamble and header field and, if so, calls ``PhyEntity::StartReceiveField ()``
for the next field,
otherwise the reception is aborted and PHY is put either in IDLE state or in CCA_BUSY state,
depending on whether a PHY-CCA.indication(BUSY) is being issued on not for the primary channel
.

The next event at ``PhyEntity::StartReceiveField ()`` checks, using the interference
helper and error model, whether the header was successfully decoded, and if so,
a ``PhyRxPayloadBegin`` callback (equivalent to the PHY-RXSTART primitive)
is triggered. The PHY header is often transmitted
at a lower modulation rate than is the payload. The portion of the packet
corresponding to the PHY header is evaluated for probability of error
based on the observed SNR.  The InterferenceHelper object returns a value
for "probability of error (PER)" for this header based on the SNR that has
been tracked by the InterferenceHelper.  The ``PhyEntity`` then draws
a random number from a uniform distribution and compares it against the
PER and decides success or failure.

This is iteratively performed up to the beginning of the data field
upon which ``PhyEntity::StartReceivePayload ()`` is called.

Even if packet objects received by the PHY are not part of the reception
process, they are tracked by the InterferenceHelper object for purposes
of SINR computation and making clear channel assessment decisions.
If, in the course of reception, a packet is errored or dropped due to
the PHY being in a state in which it cannot receive a packet, the packet
is added to the interference helper, and the aggregate of the energy of
all such signals is compared against an energy detection threshold to
determine whether the PHY should enter a CCA_BUSY state.

A PHY-CCA.indication(BUSY) is issued if a signal occupying the primary channel with a received
power above ``WifiPhy::CcaSensitivity`` (defaulted to -82 dBm) has been received by the PHY or if the
measured energy on the primary channel is higher than the energy detection threshold ``WifiPhy::CcaEdThreshold``
(defaulted to -62 dBm).

When channel bonding is used, CCA indication for signals not occupying the primary channel is also reported.
Since 802.11ac and above needs to sense CCA sensitivity for secondary channels larger than 20 MHz, CCA sensitivity thresholds
can be adjusted per secondary channel width using ``VhtConfiguration::SecondaryCcaSensitivityThresholds`` attribute.

For 802.11ax and above, and if the operational bandwidth is equal or larger than 40 MHz, each 20 MHz subchannel of the operational bandwidth
is being sensed and PHY-CCA.indication also reports a CCA_BUSY duration indication for each of these 20 MHz subchannel. A zero duration for
a given 20 MHz subchannel indicates the 20 MHz subchannel is IDLE.

The above describes the case in which the packet is a single MPDU.  For
more recent Wi-Fi standards using MPDU aggregation, ``StartReceivePayload``
schedules an event for reception of each individual MPDU (``ScheduleEndOfMpdus``),
which then forwards each MPDU as they arrive up to FrameExchangeManager, if the
reception of the MPDU has been successful. Once the A-MPDU reception is finished,
FrameExchangeManager is also notified about the amount of successfully received MPDUs.

InterferenceHelper
##################

The InterferenceHelper is an object that tracks all incoming packets and
calculates probability of error values for packets being received, and
also evaluates whether and for how long energy on the channel rises above
a given threshold.

The basic operation of probability of error calculations is shown in Figure
:ref:`snir`.  Packets are represented as bits (not symbols) in the |ns3|
model, and the InterferenceHelper breaks the packet into one or more
"chunks", each with a different signal to noise (and interference) ratio
(SNIR).  Each chunk is separately evaluated by asking for the probability
of error for a given number of bits from the error model in use.  The
InterferenceHelper builds an aggregate "probability of error" value
based on these chunks and their duration, and returns this back to
the ``WifiPhy`` for a reception decision.

.. _snir:

.. figure:: figures/snir.*

   *SNIR function over time*

From the SNIR function we can derive the Bit Error Rate (BER) and Packet
Error Rate (PER) for
the modulation and coding scheme being used for the transmission.

If MIMO is used and the number of spatial streams is lower than the number
of active antennas at the receiver, then a gain is applied to the calculated
SNIR as follows (since STBC is not used):

.. math::

  gain (dB) = 10 \log(\frac{RX \ antennas}{spatial \ streams})

Having more TX antennas can be safely ignored for AWGN. The resulting gain is:

::

  antennas   NSS    gain
  2 x 1       1     0 dB
  1 x 2       1     3 dB
  2 x 2       1     3 dB
  3 x 3       1   4.8 dB
  3 x 3       2   1.8 dB
  3 x 3       3     0 dB
  4 x 4       1     6 dB
  4 x 4       2     3 dB
  4 x 4       3   1.2 dB
  4 x 4       4     0 dB
  ...

ErrorRateModel
##############

|ns3| makes a packet error or success decision based on the input received
SNR of a frame and based on any possible interfering frames that may overlap
in time; i.e. based on the signal-to-noise (plus interference) ratio, or
SINR.  The relationship between packet error ratio (PER) and SINR in |ns3|
is defined by the ``ns3::ErrorRateModel``, of which there are several.
The PER is a function of the frame's modulation and coding (MCS), its SINR,
and the specific ErrorRateModel configured for the MCS.

|ns3| has updated its default ErrorRateModel over time.  The current
(as of ns-3.33 release) model for recent OFDM-based standards (i.e.,
802.11n/ac/ax), is the ``ns3::TableBasedErrorRateModel``.  The default
for 802.11a/g is the ``ns3::YansErrorRateModel``, and the default for
802.11b is the ``ns3::DsssErrorRateModel``.  The error rate model for
recent standards was updated during the ns-3.33 release cycle (previously,
it was the ``ns3::NistErrorRateModel``).

The error models are described in more detail in outside references.  The
current OFDM model is based on work published in [patidar2017]_, using
link simulations results from the MATLAB WLAN Toolbox, and validated against
IEEE TGn results [erceg2004]_.  For publications related to other error models,
please refer to [pei80211ofdm]_, [pei80211b]_, [lacage2006yans]_, [Haccoun]_,
[hepner2015]_ and [Frenger]_ for a detailed description of the legacy PER models.

The current |ns3| error rate models are for additive white gaussian
noise channels (AWGN) only; any potential frequency-selective fading
effects are not modeled.

In summary, there are four error models:

#. ``ns3::TableBasedErrorRateModel``: for OFDM modes and reuses
   ``ns3::DsssErrorRateModel`` for 802.11b modes.
   This is the default for 802.11n/ac/ax.
#. ``ns3::YansErrorRateModel``: for OFDM modes and reuses
   ``ns3::DsssErrorRateModel`` for 802.11b modes.
   This is the default for 802.11a/g.
#. ``ns3::DsssErrorRateModel``:  contains models for 802.11b modes.  The
   802.11b 1 Mbps and 2 Mbps error models are based on classical modulation
   analysis.  If GNU Scientific Library (GSL) is installed, the 5.5 Mbps
   and 11 Mbps from [pursley2009]_ are used for CCK modulation;
   otherwise, results from a backup MATLAB-based CCK model are used.
#. ``ns3::NistErrorRateModel``: for OFDM modes and reuses
   ``ns3::DsssErrorRateModel`` for 802.11b modes.

Users may select either NIST, YANS or Table-based models for OFDM,
and DSSS will be used in either case for 802.11b.  The NIST model was
a long-standing default in ns-3 (through release 3.32).

TableBasedErrorRateModel
########################

The ``ns3::TableBasedErrorRateModel`` has been recently added and is now the |ns3| default
for 802.11n/ac/ax, while ``ns3::YansErrorRateModel`` is the |ns3| default for 802.11a/g.

Unlike analytical error models based on error bounds, ``ns3::TableBasedErrorRateModel`` contains
end-to-end link simulation tables (PER vs SNR) for AWGN channels. Since it is infeasible to generate
such look-up tables for all desired packet sizes and input SNRs, we adopt the recommendation of IEEE P802.11 TGax [porat2016]_ that proposed
estimating PER for any desired packet length using BCC FEC encoding by extrapolating the results from two reference lengths:
32 (all lengths less than 400) bytes and 1458 (all lengths greater or equal to 400) bytes respectively.
In case of LDPC FEC encoding, IEEE P802.11 TGax recommends the use of a single reference length.
Hence, we provide two tables for BCC and one table for LDPC that are generated using a reliable and publicly
available commercial link simulator (MATLAB WLAN Toolbox) for each modulation and coding scheme.
Note that BCC tables are limited to MCS 9. For higher MCSs, the models fall back to the use of the YANS analytical model.

The validation scenario is set as follows:

#. Ideal channel and perfect channel estimation.
#. Perfect packet synchronization and detection.
#. Phase tracking, phase correction, phase noise, carrier frequency offset, power amplifier non-linearities etc. are not considered.

Several packets are simulated across the link to obtain PER, the number of packets needed to reliably
estimate a PER value is computed using the consideration that the ratio of the estimation error to the
true value should be within 10 % with probability 0.95.
For each SNR value, simulations were run until a total of 40000 packets were simulated.

The obtained results are very close to TGax curves as shown in Figure
:ref:`default-table-based-error-model-validation`

.. _default-table-based-error-model-validation:

.. figure:: figures/default-table-based-error-model-validation.*
   :scale: 75%

   *Comparison of table-based OFDM Error Model with TGax results.*

Legacy ErrorRateModels
######################

The original error rate model was called the ``ns3::YansErrorRateModel`` and
was based on analytical results.  For 802.11b modulations, the 1 Mbps mode
is based on DBPSK. BER is from equation 5.2-69 from [proakis2001]_.
The 2 Mbps model is based on DQPSK. Equation 8 of [ferrari2004]_.
More details are provided in [lacage2006yans]_.

The ``ns3::NistErrorRateModel`` was later added.
The model was largely aligned with the previous ``ns3::YansErrorRateModel``
for DSSS modulations 1 Mbps and 2 Mbps, but the 5.5 Mbps and 11 Mbps models
were re-based on equations (17) and (18) from [pursley2009]_.
For OFDM modulations, newer results were
obtained based on work previously done at NIST [miller2003]_.  The results
were also compared against the CMU wireless network emulator, and details
of the validation are provided in [pei80211ofdm]_.  Since OFDM modes use
hard-decision of punctured codes, the coded BER is calculated using
Chernoff bounds [hepner2015]_.

The 802.11b model was split from the OFDM model when the NIST error rate
model was added, into a new model called DsssErrorRateModel.

Furthermore, the 5.5 Mbps and 11 Mbps models for 802.11b rely on library
methods implemented in the GNU Scientific Library (GSL).  The ns3 build
system tries to detect whether the host platform has GSL installed; if so,
it compiles in the newer models from [pursley2009]_ for 5.5 Mbps and 11 Mbps;
if not, it uses a backup model derived from MATLAB simulations.

The error curves for analytical models are shown to diverge from link simulation results for higher MCS in
Figure :ref:`error-models-comparison`. This prompted the move to a new error
model based on link simulations (the default TableBasedErrorRateModel, which
provides curves close to those depicted by the TGn dashed line).

.. _error-models-comparison:

.. figure:: figures/error-models-comparison.*

  *YANS and NIST error model comparison with TGn results*

SpectrumWifiPhy
###############

This section describes the implementation of the ``SpectrumWifiPhy``
class that can be found in ``src/wifi/model/spectrum-wifi-phy.{cc,h}``.

The implementation also makes use of additional classes found in the
same directory:

* ``wifi-spectrum-phy-interface.{cc,h}``
* ``wifi-spectrum-signal-parameters.{cc,h}``

and classes found in the spectrum module:

* ``wifi-spectrum-value-helper.{cc,h}``

The current ``SpectrumWifiPhy`` class
reuses the existing interference manager and error rate models originally
built for ``YansWifiPhy``, but allows, as a first step, foreign (non Wi-Fi)
signals to be treated as additive noise.

Two main changes were needed to adapt the Spectrum framework to Wi-Fi.
First, the physical layer must send signals compatible with the
Spectrum channel framework, and in particular, the
``MultiModelSpectrumChannel`` that allows signals from different
technologies to coexist.  Second, the InterferenceHelper must be
extended to support the insertion of non-Wi-Fi signals and to
add their received power to the noise, in the same way that
unintended Wi-Fi signals (perhaps from a different SSID or arriving
late from a hidden node) are added to the noise.

Unlike ``YansWifiPhy``, where there are no foreign signals, CCA_BUSY state
will be raised for foreign signals that are higher than CcaEdThreshold
(see section 16.4.8.5 in the 802.11-2012 standard for definition of
CCA Mode 1).  The attribute ``WifiPhy::CcaEdThreshold`` therefore
potentially plays a larger role in this model than in the ``YansWifiPhy``
model.

To support the Spectrum channel, the ``YansWifiPhy`` transmit and receive methods
were adapted to use the Spectrum channel API.  This required developing
a few ``SpectrumModel``-related classes.  The class
``WifiSpectrumValueHelper`` is used to create Wi-Fi signals with the
spectrum framework and spread their energy across the bands. The
spectrum is sub-divided into sub-bands (the width of an OFDM
subcarrier, which depends on the technology). The power allocated to a particular channel
is spread across the sub-bands roughly according to how power would
be allocated to sub-carriers. Adjacent channels are models by the use of
OFDM transmit spectrum masks as defined in the standards.

The class ``WifiBandwidthFilter`` is used to discard signals early in the
transmission process by ignoring any Wi-Fi PPDU whose TX band (including guard bands)
does not overlap the current operating channel. Therefore, it bypasses the signal
propagation/loss calculations reducing the computational load and increasing the
simulation performance. To enable the ``WifiBandwidthFilter``, the user can use object
aggregation as follows:
.. sourcecode:: cpp

  Ptr<WifiBandwidthFilter> wifiFilter = CreateObject<WifiBandwidthFilter> ();
  Ptr<MultiModelSpectrumChannel> spectrumChannel = CreateObject<MultiModelSpectrumChannel> ();
  spectrumChannel->AddSpectrumTransmitFilter(wifiFilter);

To support an easier user configuration experience, the existing
YansWifi helper classes (in ``src/wifi/helper``) were copied and
adapted to provide equivalent SpectrumWifi helper classes.

Finally, for reasons related to avoiding C++ multiple inheritance
issues, a small forwarding class called ``WifiSpectrumPhyInterface``
was inserted as a shim between the ``SpectrumWifiPhy`` and the
Spectrum channel.  The ``WifiSpectrumPhyInterface`` calls a different
``SpectrumWifiPhy::StartRx ()`` method to start the reception process.
This method performs the check of the signal power against the
``WifiPhy::RxSensitivity`` attribute and discards weak signals, and
also checks if the signal is a Wi-Fi signal; non-Wi-Fi signals are added
to the InterferenceHelper and can raise CCA_BUSY but are not further processed
in the reception chain.   After this point, valid Wi-Fi signals cause
``WifiPhy::StartReceivePreamble`` to be called, and the processing continues
as described above.

Furthermore, in order to support more flexible channel switching,
the ``SpectrumWifiPhy`` can hold multiple instances of ``WifiSpectrumPhyInterface``
(:ref:`fig-spectrum-wifi-phy-multiple-interfaces`).
Each of these instances handles a given frequency range of the spectrum, identified by
a start and a stop frequency expressed in MHz, and there can be no overlap in spectrum between them.
Only one of these ``WifiSpectrumPhyInterface`` instances corresponds to the active RF interface of the ``SpectrumWifiPhy``,
the other ones are referred to as inactive RF interfaces and might be disconnected from the spectrum channel.

.. _fig-spectrum-wifi-phy-multiple-interfaces:

.. figure:: figures/spectrum-wifi-phy-multiple-interfaces.*
   :align: center

   Multiple RF interfaces concept

If the ``SpectrumWifiPhy::TrackSignalsFromInactiveInterfaces`` attribute is set to true (default),
inactive RF interfaces are connected to their respective spectrum channels and the ``SpectrumWifiPhy``
also receive signals from these inactive RF interfaces when they belong to a configured portion
of the frequency range covered by the interface.
The portion of the spectrum being monitored by an inactive interface is specified by a center frequency
and a channel width, and is seamlessly set to equivalent of the operating channel of the spectrum PHY
that is actively using that frequency range. The ``SpectrumWifiPhy``forwards these received signals
from inactive interfaces to the ``InterferenceHelper`` without further processing them.
The benefit of the latter is that more accurate PHY-CCA.indication can be generated upon channel switching
if one or more signals started to be transmitted on the new channel before the switch occurs,
which would be ignored otherwise. This is illustrated in Figure :ref:`fig-cca-channel-switching-multiple-interfaces`, where the parts in red are only generated when ``SpectrumWifiPhy::TrackSignalsFromInactiveInterfaces`` is set to true.

.. _fig-cca-channel-switching-multiple-interfaces:

.. figure:: figures/cca-channel-switching-multiple-interfaces.*
   :align: center

   Illustration of signals tracking upon channel switching

MU-MIMO PHY support
###################

There is a basic support for MU-MIMO at the PHY layer that has been introduced in release
ns-3.40. The current model can be used for both downlink and uplink MU-MIMO transmissions.

The use of OFDMA and MU-MIMO for Multi-User transmissions depends on how the TXVECTOR
is filled in by the MAC layer (not implemented yet). Since mixed OFDMA and MU-MIMO
configurations are not supported, the TXVECTOR determines it carries information for
MU-MIMO if all users are assigned the same RU, otherwise it corresponds to an OFDMA
transmission.

At the PHY layer, OFDMA and MU-MIMO transmissions are handled in a similar way, the main difference
lies in MU-MIMO having the same spectrum shared simultaneously with multiple transmitters (for
the uplink direction). The current PHY abstraction model assumes perfect conditions where the
interference helper is able to detect signals belonging to the same MU-MIMO transmission and make
sure they do not interfere with each others. Interference with other signals, including other
MU-MIMO transmissions, is still supported by the model.

The MAC model
=============

Infrastructure association
##########################

Association in infrastructure mode is a high-level MAC function performed by
the Association Manager, which is implemented through a base class (``WifiAssocManager``)
and a default subclass (``WifiDefaultAssocManager``). The interaction between
the station MAC, the Association Manager base class and subclass is illustrated
in Figure :ref:`fig-assoc-manager`.

.. _fig-assoc-manager:

.. figure:: figures/assoc-manager.*
   :align: center

   Scanning procedure

The STA wifi MAC requests the Association Manager to start a scanning procedure
with specified parameters, including the type of scanning (active or passive),
the desired SSID, the list of channels to scan, etc. The STA wifi MAC then expects
to be notified of the best AP to associate with at the end of the scanning procedure.
Every Beacon or Probe Response frame received during scanning is forwarded to the
Association Manager, which keeps a list of candidate APs that match the scanning
parameters. The sorting criterium for such a list is defined by the Association
Manager subclass. The default Association Manager sorts APs in decreasing order
of the SNR of the received Beacon/Probe Response frame.

When notified of the start of a scanning procedure, the default Association Manager
schedules a call to a method that processes the information included in the frames
received up to the time such a method is called. When both the AP and the STA have
multiple links (i.e., they are 802.11be MLDs), the default Association Manager attempts
to setup as many links as possible. This involves switching operating channel on some of
the STA's links to match those on which the APs affiliated with the AP MLD are operating.

If association is rejected by the AP for some reason, the STA will try to
associate to the next best AP until the candidate list is exhausted which
then sends STA to 'REFUSED' state. If this occurs, the simulation user will
need to force reassociation retry in some way, perhaps by changing
configuration (i.e. the STA will not persistently try to associate upon a
refusal).

When associated, if the configuration is changed by the simulation user,
the STA will try to reassociate with the existing AP.

If the number of missed beacons exceeds the threshold, the STA will notify
the rest of the device that the link is down (association is lost) and
restart the scanning process. Note that this can also happen when an
association request fails without explicit refusal (i.e., the AP fails to
respond to association request). In case of non-AP MLDs, in order for losing
association, it is necessary that no beacon is received on any link for an
interval of duration equal to the maximum number of missed beacons times the
interval between two consecutive Beacon frames.

Roaming
#######

Roaming at layer-2 (i.e. a STA migrates its association from one AP to
another) is not presently supported. Because of that, the Min/Max channel
dwelling time implementation as described by the IEEE 802.11 standard
[ieee80211]_ is also omitted, since it is only meaningful on the context
of channel roaming.

Channel access
##############

The 802.11 Distributed Coordination Function is used to calculate when to grant
access to the transmission medium. While implementing the DCF would have been
particularly easy if we had used a recurring timer that expired every slot, we
chose to use the method described in [ji2004sslswn]_
where the backoff timer duration is lazily calculated whenever needed since it
is claimed to have much better performance than the simpler recurring timer
solution.

The DCF basic access is described in section 10.3.4.2 of [ieee80211-2016]_.

*  “A STA may transmit an MPDU when it is operating under the DCF access method
   [..] when the STA determines that the medium is idle when a frame is queued
   for transmission, and remains idle for a period of a DIFS, or an EIFS
   (10.3.2.3.7) from the end of the immediately preceding medium-busy event,
   whichever is the greater, and the backoff timer is zero. Otherwise the random
   backoff procedure described in 10.3.4.3 shall be followed."

Thus, a station is allowed not to invoke the backoff procedure if all of the
following conditions are met:

*  the medium is idle when a frame is queued for transmission
*  the medium remains idle until the most recent of these two events: a DIFS
   from the time when the frame is queued for transmission; an EIFS from the
   end of the immediately preceding medium-busy event (associated with the
   reception of an erroneous frame)
*  the backoff timer is zero

The backoff procedure of DCF is described in section 10.3.4.3 of [ieee80211-2016]_.

*  “A STA shall invoke the backoff procedure to transfer a frame
   when finding the medium busy as indicated by either the physical or
   virtual CS mechanism.”
*  “A backoff procedure shall be performed immediately after the end of
   every transmission with the More Fragments bit set to 0 of an MPDU of
   type Data, Management, or Control with subtype PS-Poll, even if no
   additional transmissions are currently queued.”

The EDCA backoff procedure is slightly different than the DCF backoff procedure
and is described in section 10.22.2.2 of [ieee80211-2016]_. The backoff procedure
shall be invoked by an EDCAF when any of the following events occur:

*  a frame is "queued for transmission such that one of the transmit queues
   associated with that AC has now become non-empty and any other transmit queues
   associated with that AC are empty; the medium is busy on the primary channel"
*  "The transmission of the MPDU in the final PPDU transmitted by the TXOP holder
   during the TXOP for that AC has completed and the TXNAV timer has expired, and
   the AC was a primary AC"
*  "The transmission of an MPDU in the initial PPDU of a TXOP fails [..] and the
   AC was a primary AC"
*  "The transmission attempt collides internally with another EDCAF of an AC that
   has higher priority"
*  (optionally) "The transmission by the TXOP holder of an MPDU in a non-initial
   PPDU of a TXOP fails"

Additionally, section 10.22.2.4 of [ieee80211-2016]_ introduces the notion of
slot boundary, which basically occurs following SIFS + AIFSN * slotTime of idle
medium after the last busy medium that was the result of a reception of a frame
with a correct FCS or following EIFS - DIFS + AIFSN * slotTime + SIFS of idle
medium after the last indicated busy medium that was the result of a frame reception
that has resulted in FCS error, or following a slotTime of idle medium occurring
immediately after any of these conditions.

On these specific slot boundaries, each EDCAF shall make a determination to perform
one and only one of the following functions:

*  Decrement the backoff timer.
*  Initiate the transmission of a frame exchange sequence.
*  Invoke the backoff procedure due to choosing not to transmit (to be included
   in the version of the standard following IEEE 802.11-2020)
*  Invoke the backoff procedure due to an internal collision.
*  Do nothing.

Thus, if an EDCAF decrements its backoff timer on a given slot boundary and, as
a result, the backoff timer has a zero value, the EDCAF cannot immediately
transmit, but it has to wait for another slotTime of idle medium before transmission
can start.

When the Channel Access Manager determines that channel access can be granted, it
determines the largest primary channel that is considered idle based on the CCA-BUSY
indication provided by the PHY. Such an information is passed to the Frame Exchange
Manager, which in turn informs the Multi-User Scheduler (if any) and the Wifi Remote
Station Manager. As a result, PPDUs are transmitted on the largest idle primary channel.
For example, if a STA is operating on a 40 MHz channel and the secondary20 channel
is indicated to be busy, transmissions will occur on the primary20 channel.

The higher-level MAC functions are implemented in a set of other C++ classes and
deal with:

* packet fragmentation and defragmentation,
* use of the RTS/CTS protocol,
* rate control algorithm,
* connection and disconnection to and from an Access Point,
* the MAC transmission queue,
* beacon generation,
* MSDU aggregation,
* etc.

Frame Exchange Managers
#######################
As the IEEE 802.11 standard evolves, more and more features are added and it is
more and more difficult to have a single component handling all of the allowed
frame exchange sequences. A hierarchy of FrameExchangeManager classes has been
introduced to make the code clean and scalable, while avoiding code duplication.
Each FrameExchangeManager class handles the frame exchange sequences introduced
by a given amendment. The FrameExchangeManager hierarchy is depicted in Figure
:ref:`fem-hierarchy`.

.. _fem-hierarchy:

.. figure:: figures/FemHierarchy.*

   *FrameExchangeManager hierarchy*

The features supported by every FrameExchangeManager class are as follows:

* ``FrameExchangeManager`` is the base class. It handles the basic sequences
  for non-QoS stations: MPDU followed by Normal Ack, RTS/CTS and CTS-to-self,
  NAV setting and resetting, MPDU fragmentation
* ``QosFrameExchangeManager`` adds TXOP support: multiple protection setting,
  TXOP truncation via CF-End, TXOP recovery, ignore NAV when responding to an
  RTS sent by the TXOP holder
* ``HtFrameExchangeManager`` adds support for Block Ack (compressed variant),
  A-MSDU and A-MPDU aggregation, Implicit Block Ack Request policy
* ``VhtFrameExchangeManager`` adds support for S-MPDUs
* ``HeFrameExchangeManager`` adds support for the transmission and reception of
  multi-user frames via DL OFDMA and UL OFDMA, as detailed below.

.. _wifi-mu-ack-sequences:

MAC queues
##########
Each EDCA function (on QoS stations) and the DCF (on non-QoS stations) have their own
MAC queue (an instance of the ``WifiMacQueue`` class) to store packets received from
the upper layer and waiting for transmission. On QoS stations, each received packet is
assigned a User Priority based on the socket priority (see, e.g., the wifi-multi-tos or
the wifi-mac-ofdma examples), which determines the Access Category that handles the
packet. By default, wifi MAC queues support flow control, hence upper layers do not
forward a packet down if there is no room for it in the corresponding MAC queue.
Wifi MAC queues do not support dynamic queue limits (byte queue limits); therefore,
there is no backpressure into the traffic control layer until the WifiMacQueue for
an access category is completely full (i.e., when the queue depth reaches the value
of the MaxSize attribute, which defaults to 500 packets).
TCP small queues (TSQ) [corbet2012]_ is a Linux feature that provides feedback from the
Wi-Fi device to the socket layer, to control how much data is queued at the Wi-Fi
level.  |ns3| TCP does not implement TSQ, nor does the WifiNetDevice provide that
specific feedback (although some use of the existing trace sources may be enough to
support it).  Regardless, experimental tests have demonstrated that TSQ interferes with
Wi-Fi aggregation on uplink transfers [grazia2022]_.
Packets stay in the wifi MAC queue until they are acknowledged or discarded. A packet
may be discarded because, e.g., its lifetime expired (i.e., it stayed in the queue for too
long) or the maximum number of retries was reached. The maximum lifetime for a packet can
be configured via the ``MaxDelay`` attribute of ``WifiMacQueue``. There are a number of
traces that can be used to track the outcome of a packet transmission (see the corresponding
doxygen documentation):

* ``WifiMac`` trace sources: ``AckedMpdu``, ``NAckedMpdu``, ``DroppedMpdu``,
  ``MpduResponseTimeout``, ``PsduResponseTimeout``, ``PsduMapResponseTimeout``
* ``WifiMacQueue`` trace source: ``Expired``

Internally, a wifi MAC queue is made of multiple sub-queues, each storing frames of
a given type (i.e., data or management) and having a given receiver address and TID.
For single-user transmissions, the next station to serve is determined by a wifi MAC
queue scheduler (held by the ``WifiMac`` instance). A wifi MAC queue scheduler is
implemented through a base class (``WifiMacQueueScheduler``) and subclasses defining
specific scheduling policies. The default scheduler (``FcfsWifiQueueScheduler``)
gives management frames higher priority than data frames and serves data frames in a
first come first serve fashion. For multi-user transmissions (see below), scheduling
is performed by a Multi-User scheduler, which may or may not consult the wifi MAC queue
scheduler to identify the stations to serve with a Multi-User DL or UL transmission.

Multi-user transmissions
########################

Since the introduction of the IEEE 802.11ax amendment, multi-user (MU) transmissions are
possible, both in downlink (DL) and uplink (UL), by using OFDMA and/or MU-MIMO. Currently,
ns-3 only supports multi-user transmissions via OFDMA. Three acknowledgment sequences are
implemented for DL OFDMA.

The first acknowledgment sequence is made of multiple BlockAckRequest/BlockAck frames sent
as single-user frames, as shown in Figure :ref:`fig-ack-su-format-80211ax`.

.. _fig-ack-su-format-80211ax:

.. figure:: figures/ack-su-format.*
   :align: center

   Acknowledgment of DL MU frames in single-user format

For the second acknowledgment sequence, an MU-BAR Trigger Frame is sent (as a single-user
frame) to solicit BlockAck responses sent in TB PPDUs, as shown in Figure :ref:`fig-mu-bar-80211ax`.

.. _fig-mu-bar-80211ax:

.. figure:: figures/mu-bar.*
   :align: center

   Acknowledgment of DL MU frames via MU-BAR Trigger Frame sent as single-user frame

For the third acknowledgment sequence, an MU-BAR Trigger Frame is aggregated to every PSDU
included in the DL MU PPDU and the BlockAck responses are sent in TB PPDUs, as shown in
Figure :ref:`fig-aggr-mu-bar-80211ax`.

.. _fig-aggr-mu-bar-80211ax:

.. figure:: figures/aggr-mu-bar.*
   :align: center

   Acknowledgment of DL MU frames via aggregated MU-BAR Trigger Frames

For UL OFDMA, both BSRP Trigger Frames and Basic Trigger Frames are supported, as shown in
Figure :ref:`fig-ul-ofdma-80211ax`. A BSRP Trigger Frame is sent by an AP to solicit stations
to send QoS Null frames containing Buffer Status Reports. A Basic Trigger Frame is sent by an AP
to solicit stations to send data frames in TB PPDUs, which are acknowledged by the AP via a
Multi-STA BlockAck frame. Note that, in order for the two frame exchange sequences to be separated
by a SIFS (as shown in Figure :ref:`fig-ul-ofdma-80211ax`), it is necessary that the transmitting
Access Category has a non-zero TXOP Limit, there is enough remaining time in the TXOP to perform
the frame exchange sequence initiated by the Basic Trigger Frame and the Multi-User scheduler
(described next) chooses to send a Basic Trigger Frame after a BSRP Trigger Frame.

.. _fig-ul-ofdma-80211ax:

.. figure:: figures/ul-ofdma.*
   :align: center

   Frame exchange sequences using UL OFDMA

Multi-User Scheduler
####################

A new component, named **MultiUserScheduler**, is in charge of determining what frame exchange
sequence the aggregated AP has to perform when gaining a TXOP (DL OFDMA, UL OFDMA or BSRP Trigger
Frame), along with the information needed to perform the selected frame exchange sequence (e.g.,
the set of PSDUs to send in case of DL OFDMA). A TXOP is gained (some time) after requesting
channel access, which is normally done by DCF/EDCA (Txop/QosTxop) if the device has frames to transmit. In order for an AP to coordinate UL MU transmissions even without DL traffic, the
duration of the access request interval can be set to a non-zero value through the
``AccessReqInterval`` attribute. The access request interval is the interval between two
consecutive requests for channel access made by the MultiUserScheduler; such requests are made
independently of the presence of frames in the queues of the AP. It is also possible to set the
Access Category for which the MultiUserScheduler makes requests for channel access (via the
``AccessReqAc`` attribute) and to choose whether the access request interval is measured starting
from the last time the MultiUserScheduler made a request for channel access or from the last time
channel access was obtained by DCF/EDCA (via the ``DelayAccessReqUponAccess`` attribute).

``MultiUserScheduler`` is an abstract base class. Currently, the only available subclass is
**RrMultiUserScheduler**. By default, no multi-user scheduler is aggregated to an AP (hence,
OFDMA is not enabled).

Round-robin Multi-User Scheduler
################################
The Round-robin Multi-User Scheduler dynamically assigns a priority to each station to ensure
airtime fairness in the selection of stations for DL multi-user transmissions. The ``NStations``
attribute enables to set the maximum number of stations that can be the recipients of a DL
multi-user frame. Therefore, every time an HE AP accesses the channel to transmit a DL
multi-user frame, the scheduler determines the number of stations the AP has frames to send
to (capped at the value specified through the mentioned attribute) and attempts to allocate
equal sized RUs to as many such stations as possible without leaving RUs of the same size
unused. For instance, if the channel bandwidth is 40 MHz and the determined number of stations
is 5, the first 4 stations (in order of priority) are allocated a 106-tone RU each (if 52-tone
RUs were allocated, we would have three 52-tone RUs unused). If central 26-tone RUs can be
allocated (as determined by the ``UseCentral26TonesRus`` attribute), possible stations that
have not been allocated an RU are assigned one of such 26-tone RU. In the previous example,
the fifth station would have been allocated one of the two available central 26-tone RUs.

When UL OFDMA is enabled (via the ``EnableUlOfdma`` attribute), every DL OFDMA frame exchange
is followed by an UL OFDMA frame exchange involving the same set of stations and the same RU
allocation as the preceding DL multi-user frame. The transmission of a BSRP Trigger Frame can
optionally (depending on the value of the ``EnableBsrp`` attribute) precede the transmission
of a Basic Trigger Frame in order for the AP to collect information about the buffer status
of the stations.

Enhanced multi-link single radio operation (EMLSR)
##################################################

The IEEE 802.11be amendment introduced EMLSR operating mode to allow a non-AP MLD to alternate
frame exchanges over a subset of setup links identified as EMLSR links (see section 35.3.17 of
IEEE 802.11be D4.1). |ns3| supports EMLSR operations as described in the following.

Architecture of a non-AP MLD supporting EMLSR operating mode
------------------------------------------------------------

The architecture of a non-AP MLD supporting EMLSR operating mode is based on the assumption that
only one PHY instance (referred to as the *main PHY*) has full TX/RX capabilities, while the other
PHY instances (referred to as *auxiliary PHYs* or *aux PHYs* for brevity) have limited TX/RX
capabilities. As a consequence, only the main PHY is able to carry out frame exchanges with the AP
MLD. Given that frame exchanges can occur on any of the EMLSR links, the link on which the main PHY operates is dynamically switched during a simulation, as detailed below.

Enabling/disabling EMLSR mode
-----------------------------

EMLSR mode can be enabled on the links (at least two) of a non-AP MLD that supports the EMLSR
operating mode and performs ML setup with an AP MLD that supports the EMLSR operating mode. The
``EmlsrActivated`` attribute of the EHT configuration of an MLD determines whether the EMLSR
operating mode is supported by the MLD. When the ``EmlsrActivated`` attribute is set to true for
a non-AP MLD, the WifiMacHelper will install an EMLSR Manager by using the type and attribute
values configured through the ``SetEmlsrManager`` method.

EMLSR mode on the links of a non-AP MLD can be enabled or disabled by using the ``EmlsrLinkSet``
attribute of the EMLSR Manager base class (after multi-link setup, EMLSR mode is disabled by
default). Setting the ``EmlsrLinkSet`` attribute triggers the transmission of an EML Operating
Mode Notification frame to the AP to communicate the new set of EMLSR links, if ML setup has been
completed. Otherwise, the set of EMLSR links is stored and the EML Operating Mode Notification
frame is sent as soon as the ML setup is completed. Therefore, users can choose to enable EMLSR
mode on some links upon the completion of ML setup by setting the ``EmlsrLinkSet`` attribute at
(or before) initialization time; alternatively, they can leave the ``EmlsrLinkSet`` attribute
empty at initialization time and set it at runtime to enable EMLSR mode on some links at a
specific simulation time (after ML setup). The selection of the link used by the non-AP
MLD to transmit the EML Operating Mode Notification frame is done by the EMLSR Manager subclass.
The default EMLSR Manager subclass, ``DefaultEmlsrManager``, selects the link on which the main
PHY is operating. When the non-AP MLD receives the acknowledgment for the EML Operating Mode
Notification frame, it starts a timer whose duration is the transition timeout advertised by the AP MLD. When the timer expires, or the non-AP MLD receives an EML Operating Mode Notification
frame from the AP MLD, the EMLSR mode is assumed to be enabled on the requested set of links
(referred to as EMLSR links), if this set is not empty, or disabled, otherwise. The set of links
on which it is requested to enable EMLSR mode must include the link on which the main PHY is
operating; the PHY instances operating on the other links on which EMLSR mode is enabled are
considered aux PHYs.

The PHY instance acting as main PHY is configured through the ``MainPhyId`` attribute of the EMLSR
Manager base class. Such a class also enables to define the TX/RX capabilities of the aux PHYs:

* the ``AuxPhyMaxModClass`` attribute indicates the maximum modulation class supported by aux PHYs
* the ``AuxPhyChannelWidth`` attribute indicates the maximum channel width (MHz) supported by aux
  PHYs. The value of this attribute may be automatically capped based on the maximum supported
  modulation class.
* the ``AuxPhyTxCapable`` attribute indicates whether aux PHYs are capable of transmitting frames

Downlink TXOP
-------------

.. _fig-emlsr-dl-txop:

.. figure:: figures/emlsr-dl-txop.*
   :align: center

   EMLSR operations: Downlink TXOP

When an AP MLD that supports EMLSR operating mode has to initiate a frame exchange on a link with
a non-AP MLD that is operating in EMLSR mode on that link, it sends an MU-RTS Trigger Frame
soliciting a response from the non-AP MLD (and possibly others) as the initial Control frame (ICF)
for that exchange (see Figure :ref:`fig-emlsr-dl-txop`). The MU-RTS Trigger Frame is carried in a
non-HT duplicate PPDU transmitted at a rate of 6 Mbps, 12 Mbps or 24 Mbps. When the
transmission of an initial Control frame starts, the AP MLD blocks transmissions to the solicited
EMLSR clients on the EMLSR links other than the link used to transmit the initial Control frame,
so that the AP MLD does not initiate another frame exchange on such links. The MU-RTS Trigger
Frame includes a Padding field whose transmission duration is the maximum among the padding
delays advertised by all the EMLSR clients solicited by the MU-RTS Trigger Frame. The padding
delay should be long enough to allow the EMLSR client to get ready to transmit the CTS response
(e.g., make the main PHY switch to operate on the link where the DL TXOP is starting). In |ns3|,
if the ICF is received by the main PHY, no link switch occurs. If the ICF is received by an aux
PHY (as shown in Fig. :ref:`fig-emlsr-dl-txop`), the main PHY switches to operate on the link
where the TXOP is starting at the end of the reception of the ICF (including the Padding field)
and the main PHY sends the CTS response. In |ns3|, the behavior of the aux PHY that received the
ICF is determined by the EMLSR Manager subclass. The ``DefaultEmlsrManager`` class provides the
``SwitchAuxPhy`` attribute for this purpose. If this attribute is true, the aux PHY switches to
operate on the link on which the main PHY was operating and stays on such a link even after
the completion of the TXOP (as shown in Fig. :ref:`fig-emlsr-dl-txop`); if this attribute is
false, the aux PHY does not perform any switch, but the main PHY switches back to operate on
its original link once the TXOP is completed (as shown in Fig. :ref:`fig-emlsr-ul-txop`).


The frame exchange with an EMLSR client is assumed to terminate when the AP MLD does not start a
frame transmission a SIFS after the response to the last frame transmitted by the AP MLD or the
AP MLD transmits a frame that is not addressed to the EMLSR client. When a frame exchange with an
EMLSR client terminates, the AP MLD blocks transmissions on all the EMLSR links and starts a
timer whose duration is the transition delay advertised by the EMLSR client. When the timer
expires, the EMLSR client is assumed to be back to the listening operations and transmissions on
all the EMLSR links are unblocked.

The padding delay and the transition delay for an EMLSR client can be set through the
``EmlsrPaddingDelay`` attribute and the ``EmlsrTransitionDelay`` attribute of the
``EmlsrManager`` base class, respectively.

Uplink TXOP
-----------

.. _fig-emlsr-ul-txop:

.. figure:: figures/emlsr-ul-txop.*
   :align: center

   EMLSR operations: Uplink TXOP

An EMLSR client can start an UL TXOP on any of the EMLSR links. When channel access is obtained
on a link where an aux PHY is operating, the aux PHY transmits an RTS frame and then the main PHY
takes over the TXOP. Figure :ref:`fig-emlsr-ul-txop` shows that the EMLSR client obtains a TXOP on
link 1, which the main PHY is operating on. Therefore, a data frame can be sent without
protection. Clearly, the EMLSR client blocks transmissions on the other EMLSR links as soon as it
starts transmitting the data frame, while the AP MLD blocks transmissions to the EMLSR client on
the other EMLSR links as soon as it receives an MPDU from the EMLSR client. When the UL TXOP
terminates, the AP MLD starts a transition delay timer, during which it does not attempt to start
a frame exchange with the EMLSR client on any EMLSR link. The EMLSR client, instead, starts a
MediumSyncDelay timer on all the EMLSR links other than the one on which the UL TXOP was carried
out. While the MediumSyncDelay timer is running on a link, the EMLSR client can start an UL TXOP
on that link, but it can perform at most a predefined number of attempts. The duration of the
MediumSyncDelay timer, the maximum number of TXOP attempts and the threshold to be used instead
of the normal CCA sensitivity for the primary 20 MHz channel are all advertised by the AP MLD and
can be configured through the attributes of the ``EmlsrManager`` class: ``MediumSyncDuration``, ``MsdMaxNTxops`` and ``MsdOfdmEdThreshold``, respectively.

Figure :ref:`fig-emlsr-ul-txop` also shows that, afterwards, the EMLSR client obtains a TXOP on
link 0, which an aux PHY is operating on. The aux PHY transmits an RTS frame and, in the
meantime, the main PHY is switched to operate on that link, receives the CTS response and
transmits the data frame. In the example shown in Fig. :ref:`fig-emlsr-ul-txop`, the
``SwitchAuxPhy`` attribute of the ``DefaultEmlsrManager`` class is set to false. This means that
the aux PHY stays on link 0 and, therefore, no PHY is operating on link 1 while the main PHY is
carrying out the UL TXOP on link 0. Once such UL TXOP terminates, the main PHY is switched back
to operate on link 1. While the MediumSyncDelay timer is running on link 1, the EMLSR client
obtains a TXOP on link 1 and, as mandated by the 802.11be specs, sends an RTS frame. If there is
no response to the RTS frame, the EMLSR client can attempt to obtain the TXOP again and transmit
another RTS frame. However, the number of attempts performed while the MediumSyncDelay timer is
running is limited by the value advertised by the AP MLD and configured through the
``MsdMaxNTxops`` attribute of the ``EmlsrManager`` class.

Ack manager
###########

Since the introduction of the IEEE 802.11e amendment, multiple acknowledgment policies
are available, which are coded in the Ack Policy subfield in the QoS Control field of
QoS Data frames (see Section 9.2.4.5.4 of the IEEE 802.11-2016 standard). For instance,
an A-MPDU can be sent with the *Normal Ack or Implicit Block Ack Request* policy, in which
case the receiver replies with a Normal Ack or a Block Ack depending on whether the A-MPDU
contains a single MPDU or multiple MPDUs, or with the *Block Ack* policy, in which case
the receiver waits to receive a Block Ack Request in the future to which it replies with
a Block Ack.

``WifiAckManager`` is the abstract base class introduced to provide an interface
for multiple ack managers. Currently, the default ack manager is
the ``WifiDefaultAckManager``.

WifiDefaultAckManager
#####################

The ``WifiDefaultAckManager`` allows to determine which acknowledgment policy
to use depending on the value of its attributes:

* ``UseExplicitBar``: used to determine the ack policy to use when a response is needed from
  the recipient and the current transmission includes multiple frames (A-MPDU) or there are
  frames transmitted previously for which an acknowledgment is needed. If this attribute is
  true, the *Block Ack* policy is used. Otherwise, the *Implicit Block Ack Request* policy is used.
* ``BaThreshold``: used to determine when the originator of a Block Ack agreement needs to
  request a response from the recipient. A value of zero means that a response is requested
  at every frame transmission. Otherwise, a non-zero value (less than or equal to 1) means
  that a response is requested upon transmission of a frame whose sequence number is distant
  at least BaThreshold multiplied by the transmit window size from the starting sequence
  number of the transmit window.
* ``DlMuAckSequenceType``: used to select the acknowledgment sequence for DL MU frames
  (acknowledgment in single-user format, acknowledgment via MU-BAR Trigger Frame sent as
  single-user frame, or acknowledgment via MU-BAR Trigger Frames aggregated to the data
  frames).

Protection manager
##################

The protection manager is in charge of determining the protection mechanism to use,
if any, when sending a frame.

``WifiProtectionManager`` is the abstract base class introduced to provide an interface
for multiple protection managers. Currently, the default protection manager is
the ``WifiDefaultProtectionManager``.

WifiDefaultProtectionManager
############################

The ``WifiDefaultProtectionManager`` selects a protection mechanism based on the
information provided by the remote station manager.

Rate control algorithms
#######################

Multiple rate control algorithms are available in |ns3|.
Some rate control algorithms are modeled after real algorithms used in real devices;
others are found in literature.
The following rate control algorithms can be used by the MAC low layer:

Algorithms found in real devices:

* ``ArfWifiManager``
* ``OnoeWifiManager``
* ``ConstantRateWifiManager``
* ``MinstrelWifiManager``
* ``MinstrelHtWifiManager``

Algorithms in literature:

* ``IdealWifiManager``  (default for ``WifiHelper``)
* ``AarfWifiManager`` [lacage2004aarfamrr]_
* ``AmrrWifiManager`` [lacage2004aarfamrr]_
* ``CaraWifiManager`` [kim2006cara]_
* ``RraaWifiManager`` [wong2006rraa]_
* ``AarfcdWifiManager`` [maguolo2008aarfcd]_
* ``ParfWifiManager`` [akella2007parf]_
* ``AparfWifiManager`` [chevillat2005aparf]_
* ``ThompsonSamplingWifiManager`` [krotov2020rate]_

ConstantRateWifiManager
#######################

The constant rate control algorithm always uses the same
transmission mode for every packet. Users can set a desired
'DataMode' for all 'unicast' packets and 'ControlMode' for all
'request' control packets (e.g. RTS).

To specify different data mode for non-unicast packets, users
must set the 'NonUnicastMode' attribute of the
WifiRemoteStationManager.  Otherwise, WifiRemoteStationManager
will use a mode with the lowest rate for non-unicast packets.

The 802.11 standard is quite clear on the rules for selection
of transmission parameters for control response frames (e.g.
CTS and ACK).  |ns3| follows the standard and selects the rate
of control response frames from the set of basic rates or
mandatory rates. This means that control response frames may
be sent using different rate even though the ConstantRateWifiManager
is used.  The ControlMode attribute of the ConstantRateWifiManager
is used for RTS frames only.  The rate of CTS and ACK frames are
selected according to the 802.11 standard.  However, users can still
manually add WifiMode to the basic rate set that will allow control
response frames to be sent at other rates.  Please consult the
`project wiki <https://www.nsnam.org/wiki/HOWTO_add_basic_rates_to_802.11>`_ on how to do this.

Available attributes:

* DataMode (default WifiMode::OfdmRate6Mbps): specify a mode for
  all non-unicast packets
* ControlMode (default WifiMode::OfdmRate6Mbps): specify a mode for
  all 'request' control packets

IdealWifiManager
################

The ideal rate control algorithm selects the best
mode according to the SNR of the previous packet sent.
Consider node *A* sending a unicast packet to node *B*.
When *B* successfully receives the packet sent from *A*,
*B* records the SNR of the received packet into a ``ns3::SnrTag``
and adds the tag to an ACK back to *A*.
By doing this, *A* is able to learn the SNR of the packet sent to *B*
using an out-of-band mechanism (thus the name 'ideal').
*A* then uses the SNR to select a transmission mode based
on a set of SNR thresholds, which was built from a target BER and
mode-specific SNR/BER curves.

Available attribute:

* BerThreshold (default 1e-6): The maximum Bit Error Rate
  that is used to calculate the SNR threshold for each mode.

Note that the BerThreshold has to be low enough to select a robust enough MCS
(or mode) for a given SNR value, without being too restrictive on the target BER.
Indeed we had noticed that the previous default value (i.e. 1e-5) led to the
selection of HE MCS-11 which resulted in high PER.
With this new default value (i.e. 1e-6), a HE STA moving away from a HE AP has
smooth throughput decrease (whereas with 1e-5, better performance was seen further
away, which is not "ideal").

ThompsonSamplingWifiManager
###########################

Thompson Sampling (TS) is a classical solution to the Multi-Armed
Bandit problem.  `ThompsonSamplingWifiManager` implements a rate
control algorithm based on TS with the goal of providing a simple
statistics-based algorithm with a low number of parameters.

The algorithm maintains the number of successful transmissions
:math:`\alpha_i` and the number of unsuccessful transmissions
:math:`\beta_i` for each MCS :math:`i`, both of which are initially
set to zero.

To select MCS for a data frame, the algorithm draws a sample frame
success rate :math:`q_i` from the beta distribution with shape
parameters :math:`(1 + \alpha_i, 1 + \beta_i)` for each MCS and then
selects MCS with the highest expected throughput calculated as the
sample frame success rate multiplied by MCS rate.

To account for changing channel conditions, exponential decay is
applied to :math:`\alpha_i` and :math:`\beta_i`. The rate of
exponential decay is controlled with the `Decay` attribute which is
the inverse of the time constant. Default value of 1 Hz results in
using exponential window with the time constant of 1 second.  Setting
this value to zero effectively disables exponential decay and can be
used in static scenarios.

Control frames are always transmitted using the most robust MCS,
except when the standard specifies otherwise, such as for ACK frames.

As the main goal of this algorithm is to provide a stable baseline, it
does not take into account backoff overhead, inter-frame spaces and
aggregation for MCS rate calculation. For an example of a more complex
statistics-based rate control algorithm used in real devices, consider
Minstrel-HT described below.

MinstrelWifiManager
###################

The minstrel rate control algorithm is a rate control algorithm originated from
madwifi project. It is currently the default rate control algorithm of the Linux kernel.

Minstrel keeps track of the probability of successfully sending a frame of each available rate.
Minstrel then calculates the expected throughput by multiplying the probability with the rate.
This approach is chosen to make sure that lower rates are not selected in favor of the higher
rates (since lower rates are more likely to have higher probability).

In minstrel, roughly 10 percent of transmissions are sent at the so-called lookaround rate.
The goal of the lookaround rate is to force minstrel to try higher rate than the currently used rate.

For a more detailed information about minstrel, see [linuxminstrel]_.

MinstrelHtWifiManager
#####################

This is the extension of minstrel for 802.11n/ac/ax.

802.11ax OBSS PD spatial reuse
##############################

802.11ax mode supports OBSS PD spatial reuse feature.
OBSS PD stands for Overlapping Basic Service Set Preamble-Detection.
OBSS PD is an 802.11ax specific feature that allows a STA, under specific conditions,
to ignore an inter-BSS PPDU.

OBSS PD Algorithm
#################

``ObssPdAlgorithm`` is the base class of OBSS PD algorithms.
It implements the common functionalities. First, it makes sure the necessary callbacks are setup.
Second, when a PHY reset is requested by the algorithm, it performs the computation to determine the TX power
restrictions and informs the PHY object.

The PHY keeps tracks of incoming requests from the MAC to get access to the channel.
If a request is received and if PHY reset(s) indicating TX power limitations occurred
before a packet was transmitted, the next packet to be transmitted will be sent with
a reduced power. Otherwise, no TX power restrictions will be applied.

Constant OBSS PD Algorithm
##########################

Constant OBSS PD algorithm is a simple OBSS PD algorithm implemented in the ``ConstantObssPdAlgorithm`` class.

Once a HE preamble and its header have been received by the PHY, ``ConstantObssPdAlgorithm::
ReceiveHeSig`` is triggered.
The algorithm then checks whether this is an OBSS frame by comparing its own BSS color with the BSS color of the received preamble.
If this is an OBSS frame, it compares the received RSSI with its configured OBSS PD level value. The PHY then gets reset to IDLE
state in case the received RSSI is lower than that constant OBSS PD level value, and is informed about a TX power restrictions.

Note: since our model is based on a single threshold, the PHY only supports one restricted power level.

Modifying Wifi model
####################

Modifying the default wifi model is one of the common tasks when performing research.
We provide an overview of how to make changes to the default wifi model in this section.
Depending on your goal, the common tasks are (in no particular order):

* Creating or modifying the default Wi-Fi frames/headers by making changes to ``wifi-mac-header.*``.
* MAC low modification. For example, handling new/modified control frames (think RTS/CTS/ACK/Block ACK),
  making changes to two-way transaction/four-way transaction.  Users usually make changes to
  ``frame-exchange-manager.*`` or its subclasses to accomplish this.
  Handling of control frames is performed in ``FrameExchangeManager::ReceiveMpdu``.
* MAC high modification. For example, handling new management frames (think beacon/probe),
  beacon/probe generation.  Users usually make changes to ``wifi-mac.*``,``sta-wifi-mac.*``, ``ap-wifi-mac.*``, or ``adhoc-wifi-mac.*`` to accomplish this.
* Wi-Fi queue management.  The files ``txop.*`` and ``qos-txop.*`` are of interest for this task.
* Channel access management.  Users should modify the files ``channel-access-manager.*``, which grant access to
  ``Txop`` and ``QosTxop``.
* Fragmentation and RTS thresholds are handled by Wi-Fi remote station manager.  Note that Wi-Fi remote
  station manager simply indicates if fragmentation and RTS are needed.  Fragmentation is handled by
  ``Txop`` or ``QosTxop`` while RTS/CTS transaction is handled by ``FrameExchangeManager``.
* Modifying or creating new rate control algorithms can be done by creating a new child class of Wi-Fi remote
  station manager or modifying the existing ones.
