/***********************************************************************//**
 * @file		syslog.c
 * @brief		Contiene las funciones del protocolo SysLog.
 * @version		1.0
 * @date		05. Mayo. 2013
 * @author		Germán Potenza
 **************************************************************************
 *
 **********************************************************************/

/** @defgroup Syslog SysLog
 * Define las funciones del protocolo SysLog.
 *
 */

/* Syslog group ----------------------------------------------------------- */
/** @addtogroup Syslog
 * @{
 */

/* Includes ------------------------------------------------------------------- */
#include "syslog.h"
#include "lwip/opt.h"
#include "lwip/udp.h"
#include "lwip/ip_addr.h"
#include "lwip/timers.h"
#include "string.h"
#include "relojtr.h"
#include "alarmas.h"

#define SYSLOG_DELAY		5000
#define SYSLOG_PORT			514 // Puerto UDP de SysLog.
#define SYSLOG_SEVERIDAD	4 // 0:Emergency, 1:Alert, 2:Critical, 3:Error, 4:Warning, 5:Notice, 6:Informational, 7:Debug.
#define LOG_LOCAL0			(16<<3) // Facility Level 0.
#define LOG_LOCAL1			(17<<3) // Facility Level 1.
#define LOG_LOCAL2			(18<<3) // Facility Level 2.
#define LOG_LOCAL3			(19<<3) // Facility Level 3.
#define LOG_LOCAL4			(20<<3) // Facility Level 4.
#define LOG_LOCAL5			(21<<3) // Facility Level 5.
#define LOG_LOCAL6			(22<<3) // Facility Level 6.
#define LOG_LOCAL7			(23<<3) // Facility Level 7.


typedef struct {
	const char *TextoAlarma; //  Puntero al texto de alarma a enviar.
	Bool Estado; // Estado de la alarma [ ON / OFF].
	time_t Tiempo; // Fecha y hora en formato Epoch.
} syslog_buff_t;

static syslog_buff_t SysLogBuffer[10];
static uint8_t IndiceBuff = 0;
static struct udp_pcb *syslog_pcb;
ip_addr_t DireccionSLServer = {(u32_t)0x0100007f}; // (127.0.0.1) en orden inverso.

extern const char *AlmEncendida;
extern const char *AlmApagada;

/* Private Functions ----------------------------------------------------------- */
/** @defgroup SL_Funciones_Privadas Funciones Privadas de SysLog
 * @ingroup Syslog
 * @{
 */

/*********************************************************************//**
 * @brief 		Función para enviar un mensaje de SysLog.
 *
 * @param[in]	*raw Puntero de la estructura de PCB.
 * @param[in]	severidad Severidad del mensaje SysLog.
 * @param[in]	*ahora Puntero a la fecha y hora en formato Epoch.
 * @param[in]	*texto_alm Puntero al texto del alarma a enviar.
 * @param[in]	*estado_alm Puntero al texto del estado de alarma.
 * @return 		None
 **********************************************************************/
static void syslog_send( struct udp_pcb *raw_pcb, uint8_t severidad, time_t *ahora, const char *texto_alm, const char *estado_alm )
{
	struct pbuf *pbuf_syslog;
	uint16_t syslog_size = 60;

	// El PBUF debe tener el tamaño justo para el Payload.
	if (strlen(texto_alm) != 0){
		syslog_size = strlen(texto_alm) + strlen(estado_alm) + 23;
	}
	else{
		syslog_size = strlen(estado_alm) + 29;
	}

	pbuf_syslog = pbuf_alloc(PBUF_TRANSPORT, (u16_t)syslog_size, PBUF_RAM);
	if (pbuf_syslog != NULL) {
		if ((pbuf_syslog->len == pbuf_syslog->tot_len) && (pbuf_syslog->next == NULL)) {
			sprintf((char *)pbuf_syslog->payload, "<%d>%.15s %s: %s", LOG_LOCAL0 | severidad, ctime(ahora)+4, texto_alm, estado_alm); // Formato del mensaje

			udp_sendto(raw_pcb, pbuf_syslog, &DireccionSLServer, SYSLOG_PORT); // Envía el mensaje.
		}
		pbuf_free(pbuf_syslog);
	}
}

/*********************************************************************//**
 * @brief 		Función de Callback para el timer de SysLog.
 *
 * @param[in]	*arg Sin uso.
 * @return 		None
 **********************************************************************/
static void syslog_callback( void *arg )
{
	uint8_t i;
	const char *TempEst;

	LWIP_UNUSED_ARG(arg);

	for (i = 0; i < IndiceBuff; i++){
		if (SysLogBuffer[i].Estado == TRUE){
			TempEst = AlmEncendida;
		}
		else {
			TempEst = AlmApagada;
		}
		syslog_send(syslog_pcb, SYSLOG_SEVERIDAD, &SysLogBuffer[i].Tiempo, SysLogBuffer[i].TextoAlarma, TempEst);
	}
	IndiceBuff = 0;
	sys_timeout(SYSLOG_DELAY, syslog_callback, NULL);
}

/*********************************************************************//**
 * @brief 		Función para inicializar el PCB de UDP para SysLog.
 *
 * @param		None
 * @return 		None
 **********************************************************************/
static void syslog_raw_init( void )
{
	syslog_pcb = udp_new();
	LWIP_ASSERT("syslog_pcb != NULL", syslog_pcb != NULL);
	sys_timeout(SYSLOG_DELAY, syslog_callback, NULL);
}

/**
 * @} end of SL_Funciones_Privadas group
 */

/*********************************************************************//**
 * @brief 		Función para enviar un mensaje de SysLog desde otro módulo.
 *
 * @param[in]	*Texto_Alm Puntero al texto del alarma a enviar.
 * @param[in]	*Estado_Alm Estado de alarma.
 * @return 		None
 **********************************************************************/
void syslog_send_later( const char *Texto_Alm, Bool Estado_Alm )
{
	if (IndiceBuff < 10){
		SysLogBuffer[IndiceBuff].TextoAlarma = Texto_Alm;
		SysLogBuffer[IndiceBuff].Estado = Estado_Alm;
		GetTiempoEpoch(&SysLogBuffer[IndiceBuff].Tiempo);
		IndiceBuff++;
	}
}

/*********************************************************************//**
 * @brief 		Función para inicializar el SysLog.
 *
 * @param		None
 * @return 		None
 **********************************************************************/
void syslog_init(void)
{
	syslog_raw_init();
}

/**
 * @} end of Syslog group
 */

/* --------------------------------- End Of File ------------------------------ */
