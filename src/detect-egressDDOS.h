/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author ATIS-DDOS-TEAM
 */
#include <time.h>
#ifndef _DETECT_EDDOS_H
#define	_DETECT_EDDOS_H

#define EDDOS_HASH_SIZE 32768

typedef struct DetecteDDOSSig_ {
    uint64_t max_numpackets; /**< max number of allowed packets */
    time_t PeriodStart;/** < start time of this periode */
    //uint64_t max_tcppackets; /**< max number of allowed tcp packets */
    float max_verhaeltnis_udp_packets; /**< max number of allowed udp packets */
    float max_abweichung_syn_ack; /**< maximale abweichung vom theoretischem 1:3 Verhältniss bei TCP Handshake. this is parsed as arg1 */
    float max_icmp_echo_req_packets; /**< verhältnis von icmp echo request packets zu allen packeten. this is parsed as arg2  */
    //uint64_t max_icmp_port_unreachable; /**< max number of allowed icmp  */
    //uint64_t max_tcp_ack_packets; /**< max number of allowed tcp_ack packets */
    //uint64_t max_tcp_syn_packets; /**< max number of allows tcp_syn packets */
} DetecteDDOSSig;

typedef struct DetecteDDOSData_ {
    uint64_t cnt_packets; /** < number of packets sent */
    uint64_t cnt_tcp; /** < number of tcp packets sent */
    uint64_t cnt_udp; /** < number of udp packets sent */
    uint64_t cnt_icmp_echo_req; /** < number of icmp echo request packets sent */
    uint64_t cnt_tcp_ack; /** < number of tcp ack packets sent */
    uint64_t cnt_tcp_syn; /** < number of tcp syn packets sent */

} DetecteDDOSData;

void DetecteDDOSRegister(void);

#endif	/* _DETECT_DUMMY_H */

