/***********************************************************************//**
 * @file		syslog.h
 * @brief		Contiene los headers de las funciones del protocolo SysLog.
 * @version		1.0
 * @date		05. Mayo. 2013
 * @author		Germán Potenza
 **************************************************************************
 *
 **********************************************************************/

#ifndef SYSLOG_H_
#define SYSLOG_H_

#include "lpc_types.h"

/* Public Functions ----------------------------------------------------------- */
/** @defgroup Syslog_Funciones_Publicas Funciones Públicas de SysLog
 * @ingroup Syslog
 * @{
 */

/** @addtogroup Syslog_Funciones_Publicas
 * @{
 */

void syslog_init( void );
void syslog_send_later( const char *Texto_Alm, Bool Estado_Alm );

/**
 * @} end of Watchdog_Funciones_Publicas group
 */

#endif /* SYSLOG_H_ */

/* --------------------------------- End Of File ------------------------------ */

