/***********************************************************************//**
 * @file		lwIP_Apps.c
 * @brief		Inicia las aplicaciones de lwIP y contiene las funciones de SSI y CGI.
 * @version		1.0
 * @date		10. Diciembre. 2012
 * @author		Germán Potenza
 **************************************************************************
 *
 **********************************************************************/

/** @defgroup Inicio_lwIP Inicio de Aplicaciones lwIP
 * @ingroup lwIP
 * Inicia las aplicaciones de lwIP y contiene las funciones de SSI y CGI.
 *
 */

/* Inicio_lwIP group ----------------------------------------------------------- */
/** @addtogroup Inicio_lwIP
 * @{
 */

/* Includes ------------------------------------------------------------------- */
#include <string.h>
#include <stdlib.h>
#include "FreeRTOS.h"
#include "FreeRTOS_IO.h"
#include "task.h"
#include "semphr.h"
#include "lwip/opt.h"
#include "lwip/tcpip.h"
#include "lwip/snmp_msg.h"
#include "netif/etharp.h"
#include "apps/httpserver_raw/httpd.h"
#include "apps/sntp/sntp.h"
#include "GPIO-output-and-software-timers.h"
#include "temperatura.h"
#include "potencia.h"
#include "relojtr.h"
#include "alarmas.h"
//#include "SPI-interface-to-SD-card.h"
//#include "watchdog.h"
#include "apps/ping/ping.h"
#include "apps/syslog/syslog.h"

/* Configuración IP por default. */
uint8_t configIP_ADDR[4] 	= { 192, 168, 1  , 200 };
uint8_t configNET_MASK[4] 	= { 255, 255, 255, 0   };
uint8_t configGW_IP_ADDR[4] = { 192, 168, 1  , 1   };
//uint8_t configSYSLOG_ADDR[4]= { 192, 168, 1  , 77  };

#define LWIP_PORT_INIT_IPADDR(addr)   IP4_ADDR((addr), configIP_ADDR[0], configIP_ADDR[1], configIP_ADDR[2], configIP_ADDR[3] )
#define LWIP_PORT_INIT_GW(addr)       IP4_ADDR((addr), configGW_IP_ADDR[0], configGW_IP_ADDR[1], configGW_IP_ADDR[2], configGW_IP_ADDR[3] )
#define LWIP_PORT_INIT_NETMASK(addr)  IP4_ADDR((addr), configNET_MASK[0],configNET_MASK[1],configNET_MASK[2],configNET_MASK[3])
#define LWIP_MAC_ADDR_BASE            { configMAC_ADDR0, configMAC_ADDR1, configMAC_ADDR2, configMAC_ADDR3, configMAC_ADDR4, configMAC_ADDR5 }

/* Definiciones de las funciones de callback de SSI. */
#define ssiTASK_STATS_INDEX			0
#define ssiRUN_TIME_STATS_INDEX		1
#define ssiSW_IO_STAT_INDEX			2
#define ssiTEMPE_GET_INDEX			3
#define ssiPOAC_GET_INDEX			4
#define ssiTIEMPO_GET_INDEX			5
#define ssiAMBIENTE_UMB_INDEX		6
#define ssiVAC_UMB_INDEX			7
#define ssiCONTACT_CFG_INDEX		8
#define ssiFECHA_GET_INDEX			9
#define ssiLOG_INSERT_TE_INDEX		10
#define ssiLOG_INSERT_AC_INDEX		11
#define ssiIPADDR_GET_INDEX			12
#define ssiIPSNTP_GET_INDEX			13
#define ssiAAC1_UMB_INDEX			14
#define ssiAAC2_UMB_INDEX			15
#define ssiVDC_UMB_INDEX			16
#define ssiADC1_UMB_INDEX			17
#define ssiADC2_UMB_INDEX			18
#define ssiLOG_INSERT_DC_INDEX		19
#define ssiPODC_GET_INDEX			20
#define ssiHUME_GET_INDEX			21
#define ssiRELE1_STAT_INDEX			22
#define ssiRELE2_STAT_INDEX			23
#define ssiRELE3_STAT_INDEX			24
#define ssiRELE4_STAT_INDEX			25
#define ssiWDHAB_GET_INDEX			26
#define ssiWDIP_GET_INDEX			27
#define ssiWDTIME_GET_INDEX			28
#define ssiIPSL_GET_INDEX			29

/*
 * The function that implements the lwIP based sockets command interpreter
 * server.
 */
extern void vBasicSocketsCommandInterpreterTask( void *pvParameters );

/*
 * The SSI handler callback function passed to lwIP.
 */
static uint16_t uslwIPAppsSSIHandler( int iIndex, char *pcBuffer, int iBufferLength );


extern float UmbralTempeMax;
extern float UmbralTempeMin;
extern float UmbralHumedadMax;
extern float UmbralHumedadMin;
extern float UmbralTensionRMSacMax;
extern float UmbralTensionRMSacMin;
extern float UmbralTensionPpAcMax;
extern float UmbralTensionPnAcMax;
extern float UmbralTensionPpAcMin;
extern float UmbralTensionPnAcMin;
extern float UmbralFrecuenciaMax;
extern float UmbralFrecuenciaMin;
extern float UmbralCorrienteRMSac1Max;
extern float UmbralCorrienteRMSac1Min;
extern float UmbralCorrientePpAc1Max;
extern float UmbralCorrientePnAc1Max;
extern float UmbralCorrientePpAc1Min;
extern float UmbralCorrientePnAc1Min;
extern float UmbralCorrienteRMSac2Max;
extern float UmbralCorrienteRMSac2Min;
extern float UmbralCorrientePpAc2Max;
extern float UmbralCorrientePnAc2Max;
extern float UmbralCorrientePpAc2Min;
extern float UmbralCorrientePnAc2Min;
extern float UmbralTensionDCMax;
extern float UmbralTensionDCMin;
extern float UmbralCorrienteDC1Max;
extern float UmbralCorrienteDC1Min;
extern float UmbralCorrienteDC2Max;
extern float UmbralCorrienteDC2Min;
extern Bool SwNormalAbierto[];
extern int32_t FechaLog[3];
extern char sntp_direccion1[];
extern char sntp_direccion2[];
extern int8_t ZhOffset;
extern Bool HabilitaPing[];
extern ip_addr_t DireccionPing[];
extern uint8_t UmbralPing;
extern uint16_t DeltaP;
extern uint16_t DeltaOff;
extern uint8_t NumAlarmaWD[];
extern ip_addr_t DireccionSLServer;

/* Strings de SSI embebidos en los archivos html.
El orden dentro del vector coincide con el índice definido anteriormente. */
static const char *pccSSITags[] = 
{
	"rtos_stats",
	"run_stats",
	"sw_stat",
	"tempe_get",
	"poac_get",
	"tiempo_get",
	"ambiente_umb",
	"vac_umb",
	"contact_cfg",
	"fecha_get",
	"log_te_insert",
	"log_ac_insert",
	"ipaddr_get",
	"ipsntp_get",
	"aac1_umb",
	"aac2_umb",
	"vdc_umb",
	"adc1_umb",
	"adc2_umb",
	"log_dc_insert",
	"podc_get",
	"hume_get",
	"rele1_stat",
	"rele2_stat",
	"rele3_stat",
	"rele4_stat",
	"wdhab_get",
	"wdip_get",
	"wdtime_get",
	"ipsl_get"
};

/* Constantes para usar con CGI */
static char const *cgi_reles(int index, int numParams, char *param[], char *value[]);
static char const *cgi_tiempo(int index, int numParams, char *param[], char *value[]);
static char const *cgi_ambiente(int index, int numParams, char *param[], char *value[]);
static char const *cgi_contact(int index, int numParams, char *param[], char *value[]);
static char const *cgi_vac(int index, int numParams, char *param[], char *value[]);
static char const *cgi_aac1(int index, int numParams, char *param[], char *value[]);
static char const *cgi_aac2(int index, int numParams, char *param[], char *value[]);
static char const *cgi_vdc(int index, int numParams, char *param[], char *value[]);
static char const *cgi_adc1(int index, int numParams, char *param[], char *value[]);
static char const *cgi_adc2(int index, int numParams, char *param[], char *value[]);
static char const *cgi_histo(int index, int numParams, char *param[], char *value[]);
static char const *cgi_ipaddr(int index, int numParams, char *param[], char *value[]);
static char const *cgi_ipsntp(int index, int numParams, char *param[], char *value[]);
static char const *cgi_ipsl(int index, int numParams, char *param[], char *value[]);
static char const *cgi_guardar(int index, int numParams, char *param[], char *value[]);
static char const *cgi_wdhab(int index, int numParams, char *param[], char *value[]);
static char const *cgi_wdip(int index, int numParams, char *param[], char *value[]);
static char const *cgi_wdtime(int index, int numParams, char *param[], char *value[]);

static tCGI const uslwIPAppsCGIHandlers[] = {
    {"/reles.cgi", cgi_reles},
    {"/tiempo.cgi", cgi_tiempo},
    {"/ambiente.cgi", cgi_ambiente},
    {"/contact.cgi", cgi_contact},
    {"/vac.cgi", cgi_vac},
    {"/aac1.cgi", cgi_aac1},
    {"/aac2.cgi", cgi_aac2},
    {"/vdc.cgi", cgi_vdc},
    {"/adc1.cgi", cgi_adc1},
    {"/adc2.cgi", cgi_adc2},
    {"/histo.cgi", cgi_histo},
    {"/ipaddr.cgi", cgi_ipaddr},
    {"/ipsntp.cgi", cgi_ipsntp},
    {"/ipsl.cgi", cgi_ipsl},
    {"/guardar.cgi", cgi_guardar},
    {"/wdhab.cgi", cgi_wdhab},
    {"/wdip.cgi", cgi_wdip},
    {"/wdtime.cgi", cgi_wdtime},
};

void prvInsertarLogTemperatura( signed char *pcWriteBuffer );
void prvInsertarLogEnergiaAC( signed char *pcWriteBuffer );
void prvInsertarLogEnergiaDC( signed char *pcWriteBuffer );
void prvInsertarDireccionesIP( signed char *pcWriteBuffer );
void prvInsertarDireccionesSNTP( signed char *pcWriteBuffer );
void prvInsertarDireccionSL( signed char *pcWriteBuffer );

static struct netif xNetIf;

/*********************************************************************//**
 * @brief 		Inicio de aplicaciones de lwIP, llamada desde el inicio de TCP/IP.
 *
 * @param		*pvArgument Argumentos de inicio.
 * @return 		None
 **********************************************************************/
void lwIPAppsInit( void *pvArgument )
{
ip_addr_t xIPAddr, xNetMask, xGateway;
//ip_addr_t xSNMP_Trap1;
extern err_t ethernetif_init( struct netif *xNetIf );
struct ip_addr ipTemp;

	( void ) pvArgument; //Para evitar el warning del compilador.

	/* Set up de la interface de red. */
	ip_addr_set_zero( &xGateway );
	ip_addr_set_zero( &xIPAddr );
	ip_addr_set_zero( &xNetMask );

	LWIP_PORT_INIT_GW(&xGateway);
	LWIP_PORT_INIT_IPADDR(&xIPAddr);
	LWIP_PORT_INIT_NETMASK(&xNetMask);

	netif_set_default( netif_add( &xNetIf, &xIPAddr, &xNetMask, &xGateway, NULL, ethernetif_init, tcpip_input ) );
	netif_set_up( &xNetIf );

	// Cambiar la dirección IP por si se lee otra desde config.txt.
	IP4_ADDR(&ipTemp, configIP_ADDR[0], configIP_ADDR[1], configIP_ADDR[2], configIP_ADDR[3]);
	netif_set_ipaddr(&xNetIf, &ipTemp);

	// Cambiar la Máscara por si se lee otra desde config.txt.
	IP4_ADDR(&ipTemp, configNET_MASK[0], configNET_MASK[1], configNET_MASK[2], configNET_MASK[3]);
	netif_set_netmask(&xNetIf, &ipTemp);

	// Cambiar el Default Gateway por si se lee otro desde config.txt.
	IP4_ADDR(&ipTemp, configGW_IP_ADDR[0], configGW_IP_ADDR[1], configGW_IP_ADDR[2], configGW_IP_ADDR[3]);
	netif_set_gw(&xNetIf, &ipTemp);

	/* Instalar el manejador de SSI. */
	http_set_ssi_handler( uslwIPAppsSSIHandler, pccSSITags, sizeof( pccSSITags ) / sizeof( char * ) );

	/* Instalar el manejador de CGI. */
	http_set_cgi_handlers(uslwIPAppsCGIHandlers, sizeof(uslwIPAppsCGIHandlers) / sizeof(tCGI));

	/* Crear el servidor http. */
	httpd_init();

	/* Crear el servidor de TELNET usando sockets de la API lwIP. */
	//xTaskCreate( vBasicSocketsCommandInterpreterTask, ( int8_t * ) "CmdInt", configCOMMAND_INTERPRETER_STACK_SIZE, NULL, configCOMMAND_INTERPRETER_TASK_PRIORITY, NULL );

	/* Inicial el módulo de PING. */
	ping_init();

	/* Inicial el módulo de SNTP. */
	sntp_init();

	/* Inicial el módulo de SysLog. */
	//IP4_ADDR(&ipTemp, configSYSLOG_ADDR[0], configSYSLOG_ADDR[1], configSYSLOG_ADDR[2], configSYSLOG_ADDR[3]);
	//syslog_init(&SysLog_Skel ,ipTemp);
	syslog_init();

	/* Define dirección de destino para Traps SNMP. */
	//xSNMP_Trap1.addr = (u32_t)0xc0a8014d; //192.168.1.77
	//snmp_trap_dst_ip_set(0, &xSNMP_Trap1);
	//snmp_trap_dst_enable(0, 1);

}

/*********************************************************************//**
 * @brief 		Función de callback del manejador de SSI.
 *
 * @param[in]	iIndex Índice del tag SSI definido.
 * @param		*pcBuffer Puntero del buffer donde se escribe el texto generado.
 * @param		iBufferLength Tamaño del buffer de escritura.
 * @return 		Tamaño del buffer de escritura con el texto generado.
 **********************************************************************/
static uint16_t uslwIPAppsSSIHandler( int iIndex, char *pcBuffer, int iBufferLength )
{
static unsigned int uiUpdateCount = 0;
static char cUpdateString[ 200 ];
extern char *pcMainGetTaskStatusMessage( void );

	( void ) iBufferLength; //Para evitar el warning del compilador.

	switch( iIndex )
	{
		case ssiTASK_STATS_INDEX : /* Para ejecutar el SSI de estadísticas de tareas */
			vTaskList( ( int8_t * ) pcBuffer );
			break;

		case ssiRUN_TIME_STATS_INDEX : /* Para ejecutar el SSI de estadísticas de tiempo de tareas */
			vTaskGetRunTimeStats( ( int8_t * ) pcBuffer );
			break;

		case ssiSW_IO_STAT_INDEX : /* Para ejecutar el SSI de SW */
			GetSwStat( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiTEMPE_GET_INDEX : /* Para ejecutar el SSI de Temperatura */
			GetTemperatura( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiPOAC_GET_INDEX : /* Para ejecutar el SSI de Potencia de AC */
			GetPotenciaAC( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiTIEMPO_GET_INDEX : /* Para ejecutar el SSI de Fecha y hora */
			GetTiempo( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiAMBIENTE_UMB_INDEX : /* Para ejecutar el SSI de Umbrales del ambiente */
			UmbAmbiente( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiVAC_UMB_INDEX : /* Para ejecutar el SSI de Umbrales de Tensión AC */
			UmbTensionAC( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiCONTACT_CFG_INDEX : /* Para ejecutar el SSI de Configuración de Contactos */
			CfgContacto( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiFECHA_GET_INDEX : /* Para ejecutar el SSI de Fecha */
			GetFechaSSI( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;
		case ssiLOG_INSERT_TE_INDEX : /* Para ejecutar el SSI de Insertar Log de ambiente */
			prvInsertarLogTemperatura( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiLOG_INSERT_AC_INDEX : /* Para ejecutar el SSI de Insertar Log de Energía AC */
			prvInsertarLogEnergiaAC( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiIPADDR_GET_INDEX : /* Para ejecutar el SSI de Insertar las direcciones IP */
			prvInsertarDireccionesIP( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiIPSNTP_GET_INDEX : /* Para ejecutar el SSI de Insertar las direcciones IP */
			prvInsertarDireccionesSNTP( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiAAC1_UMB_INDEX : /* Para ejecutar el SSI de Umbrales de Corriente AC1 */
			UmbCorrienteAC1( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiAAC2_UMB_INDEX : /* Para ejecutar el SSI de Umbrales de Corriente AC2 */
			UmbCorrienteAC2( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiVDC_UMB_INDEX : /* Para ejecutar el SSI de Umbrales de Tensión DC */
			UmbTensionDC( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiADC1_UMB_INDEX : /* Para ejecutar el SSI de Umbrales de Corriente DC1 */
			UmbCorrienteDC1( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiADC2_UMB_INDEX : /* Para ejecutar el SSI de Umbrales de Corriente DC2 */
			UmbCorrienteDC2( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiLOG_INSERT_DC_INDEX : /* Para ejecutar el SSI de Insertar Log de Energía DC */
			prvInsertarLogEnergiaDC( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiPODC_GET_INDEX : /* Para ejecutar el SSI de Potencia de DC */
			GetPotenciaDC( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiHUME_GET_INDEX : /* Para ejecutar el SSI de Humedad */
			GetHumedad( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiRELE1_STAT_INDEX : /* Para ejecutar el SSI del Rele1 */
			GetReleStat( 0, ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiRELE2_STAT_INDEX : /* Para ejecutar el SSI del Rele2 */
			GetReleStat( 1, ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiRELE3_STAT_INDEX : /* Para ejecutar el SSI del Rele3 */
			GetReleStat( 2, ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiRELE4_STAT_INDEX : /* Para ejecutar el SSI del Rele4 */
			GetReleStat( 3, ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiWDHAB_GET_INDEX : /* Para ejecutar el SSI de Habilitación WD */
			GetWDHab( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiWDIP_GET_INDEX : /* Para ejecutar el SSI de direcciones IP WD */
			GetWDIP( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiWDTIME_GET_INDEX : /* Para ejecutar el SSI de Timers WD */
			GetWDTime( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;

		case ssiIPSL_GET_INDEX : /* Para ejecutar el SSI de dirección IP de SysLog */
			prvInsertarDireccionSL( ( int8_t * ) pcBuffer );
			return strlen( pcBuffer );
			break;
	}

	/* Contador para los SSI de estadísticas de tareas. */
	uiUpdateCount++;
	sprintf( cUpdateString, "\r\n\r\nRefresh count %u", uiUpdateCount );
	strcat( pcBuffer, cUpdateString );
	return strlen( pcBuffer );
}

/*********************************************************************//**
 * @brief 		Función para ejecutar al invocar reles.cgi.
 *
 * @param[in]	index Índice dentro de los parámetros de CGI recibidos.
 * @param[in]	numParams Número de parámetros CGI recibidos.
 * @param[in]	*param[] Puntero al vector con los parámetros CGI recibidos.
 * @param[in]	*value[] Puntero al vector con los valores de los parámetros CGI recibidos.
 * @return 		Nombre de la página html que devuelve al finalizar.
 **********************************************************************/
static char const *cgi_reles(int index, int numParams, char *param[], char *value[])
{
    int i;
    uint8_t Retorno = 0;
    uint8_t Estado = 0;

    (void) index; // Solo para evitar el warning del compilador.

    for (i = 0; i < numParams; ++i) {
        if (strstr(param[i], "origen") != (char *)0) {   /* parámetro encontrado */
			if (strcmp(value[i], "ac1") == 0) {
				Retorno = 1;
			}
			else if (strcmp(value[i], "ac2") == 0) {
				Retorno = 2;
			}
			else if (strcmp(value[i], "dc1") == 0) {
				Retorno = 3;
			}
			else if (strcmp(value[i], "dc2") == 0) {
				Retorno = 4;
			}
		}
        if (strstr(param[i], "rele") != (char *)0) {   /* parámetro encontrado */
            if (strstr(value[i], "on") != (char *)0){
            	Estado = 1;
            }
            else if (strstr(value[i], "off") != (char *)0){
            	Estado = 2;
             }
        }
    }

    if ((Retorno > 0) && (Estado > 0)) {
    	if (Estado == 1){
    		SetReleStat(Retorno-1);
    	}
    	else if (Estado == 2){
    		ClrReleStat(Retorno-1);
    	}
    }

    switch (Retorno){
    case 1 ... 2:
    	return "/enerac.ssi";
    	break;

    case 3 ... 4:
		return "/enerdc.ssi";
		break;

    default:
    	return (char *)0;/*si no se encuentra el URI, HTTPD envía error 404*/
    }
}

/*********************************************************************//**
 * @brief 		Función para ejecutar al invocar tiempo.cgi.
 *
 * @param[in]	index Índice dentro de los parámetros de CGI recibidos.
 * @param[in]	numParams Número de parámetros CGI recibidos.
 * @param[in]	*param[] Puntero al vector con los parámetros CGI recibidos.
 * @param[in]	*value[] Puntero al vector con los valores de los parámetros CGI recibidos.
 * @return 		Nombre de la página html que devuelve al finalizar.
 **********************************************************************/
/* TODO: Mejorar la validación de los datos que llegan. */

static char const *cgi_tiempo(int index, int numParams, char *param[], char *value[])
{
	RTC_TIME_Type TiempoFull;
	uint32_t i = 0;
	uint32_t j = 0;
	char cTempString[ 5 ];
	uint32_t DatoTemporal;

	(void) index;     // Solo para evitar el warning del compilador.
	(void) numParams; // Solo para evitar el warning del compilador.

	RTC_GetFullTime(LPC_RTC, &TiempoFull);

	if (strstr(param[0], "dia") != (char *)0) {   /* parámetro encontrado */
		strcpy(cTempString, value[0]);
		if ((cTempString[0] >= '0' && cTempString[0] <= '9' && cTempString[1] >= '0' && cTempString[1] <= '9') || cTempString[1] == 0){
			DatoTemporal = 0;
			for (j = 0; j < strlen(cTempString); ++j) {
				DatoTemporal = (DatoTemporal*10) + (cTempString[j]-'0');
			}
			TiempoFull.DOM = DatoTemporal;
			i++;
		}
	}
	if (strstr(param[1], "mes") != (char *)0) {   /* parámetro encontrado */
		strcpy(cTempString, value[1]);
		if ((cTempString[0] >= '0' && cTempString[0] <= '9' && cTempString[1] >= '0' && cTempString[1] <= '9') || cTempString[1] == 0){
			DatoTemporal = 0;
			for (j = 0; j < strlen(cTempString); ++j) {
				DatoTemporal = (DatoTemporal*10) + (cTempString[j]-'0');
			}
			TiempoFull.MONTH = DatoTemporal;
			i++;
		}
	}
	if (strstr(param[2], "anio") != (char *)0) {   /* parámetro encontrado */
		strcpy(cTempString, value[2]);
		if (cTempString[0] >= '0' && cTempString[0] <= '9' && cTempString[1] >= '0' && cTempString[1] <= '9' && cTempString[2] >= '0' && cTempString[2] <= '9' && cTempString[3] >= '0' && cTempString[3] <= '9'){
			DatoTemporal = 0;
			for (j = 0; j < strlen(cTempString); ++j) {
				DatoTemporal = (DatoTemporal*10) + (cTempString[j]-'0');
			}
			TiempoFull.YEAR = DatoTemporal;
			i++;
		}
	}
	if (strstr(param[3], "hora") != (char *)0) {   /* parámetro encontrado */
		strcpy(cTempString, value[3]);
		if ((cTempString[0] >= '0' && cTempString[0] <= '9' && cTempString[1] >= '0' && cTempString[1] <= '9') || cTempString[1] == 0){
			DatoTemporal = 0;
			for (j = 0; j < strlen(cTempString); ++j) {
				DatoTemporal = (DatoTemporal*10) + (cTempString[j]-'0');
			}
			TiempoFull.HOUR = DatoTemporal;
			i++;
		}
	}
	if (strstr(param[4], "minutos") != (char *)0) {   /* parámetro encontrado */
		strcpy(cTempString, value[4]);
		if ((cTempString[0] >= '0' && cTempString[0] <= '9' && cTempString[1] >= '0' && cTempString[1] <= '9') || cTempString[1] == 0){
			DatoTemporal = 0;
			for (j = 0; j < strlen(cTempString); ++j) {
				DatoTemporal = (DatoTemporal*10) + (cTempString[j]-'0');
			}
			TiempoFull.MIN = DatoTemporal;
			i++;
		}
	}
	if (strstr(param[5], "segundos") != (char *)0) {   /* parámetro encontrado */
		strcpy(cTempString, value[5]);
		if ((cTempString[0] >= '0' && cTempString[0] <= '9' && cTempString[1] >= '0' && cTempString[1] <= '9') || cTempString[1] == 0){
			DatoTemporal = 0;
			for (j = 0; j < strlen(cTempString); ++j) {
				DatoTemporal = (DatoTemporal*10) + (cTempString[j]-'0');
			}
			TiempoFull.SEC = DatoTemporal;
			i++;
		}
	}

	if (i==6){
		SetTiempo(&TiempoFull);
		return "/sistema.ssi";
	}
	else {
		return (char *)0;/*si no se encuentra el URI, HTTPD envía error 404*/
	}
}

/*********************************************************************//**
 * @brief 		Función para ejecutar al invocar ambiente.cgi.
 *
 * @param[in]	index Índice dentro de los parámetros de CGI recibidos.
 * @param[in]	numParams Número de parámetros CGI recibidos.
 * @param[in]	*param[] Puntero al vector con los parámetros CGI recibidos.
 * @param[in]	*value[] Puntero al vector con los valores de los parámetros CGI recibidos.
 * @return 		Nombre de la página html que devuelve al finalizar.
 **********************************************************************/
static char const *cgi_ambiente(int index, int numParams, char *param[], char *value[])
{
    int i;
    Bool HabTMax = FALSE;
    Bool HabTMin = FALSE;
    Bool HabHMax = FALSE;
    Bool HabHMin = FALSE;

    (void) index; // Solo para evitar el warning del compilador.

    for (i = 0; i < numParams; ++i) {
        if (strstr(param[i], "tmax") != (char *)0) {   /* parámetro encontrado */
        	UmbralTempeMax = (float) atof( value[i] );
        }
        if (strstr(param[i], "tmin") != (char *)0) {   /* parámetro encontrado */
        	UmbralTempeMin = (float) atof( value[i] );
        }
        if (strstr(param[i], "hab1") != (char *)0) {   /* parámetro encontrado */
        	HabTMax = TRUE;
        }
        if (strstr(param[i], "hab2") != (char *)0) {   /* parámetro encontrado */
        	HabTMin = TRUE;
        }
        if (strstr(param[i], "hmax") != (char *)0) {   /* parámetro encontrado */
			UmbralHumedadMax = (float) atof( value[i] );
		}
		if (strstr(param[i], "hmin") != (char *)0) {   /* parámetro encontrado */
			UmbralHumedadMin = (float) atof( value[i] );
		}
		if (strstr(param[i], "hab3") != (char *)0) {   /* parámetro encontrado */
			HabHMax = TRUE;
		}
		if (strstr(param[i], "hab4") != (char *)0) {   /* parámetro encontrado */
			HabHMin = TRUE;
		}
    }
    HabilitarAlarma(32, HabTMax);
    HabilitarAlarma(33, HabTMin);
    HabilitarAlarma(34, HabHMax);
    HabilitarAlarma(35, HabHMin);
    return "/ambiente.ssi";
}

/*********************************************************************//**
 * @brief 		Función para ejecutar al invocar contact.cgi.
 *
 * @param[in]	index Índice dentro de los parámetros de CGI recibidos.
 * @param[in]	numParams Número de parámetros CGI recibidos.
 * @param[in]	*param[] Puntero al vector con los parámetros CGI recibidos.
 * @param[in]	*value[] Puntero al vector con los valores de los parámetros CGI recibidos.
 * @return 		Nombre de la página html que devuelve al finalizar.
 **********************************************************************/
static char const *cgi_contact(int index, int numParams, char *param[], char *value[])
{
    int i;
    Bool HabAlarma[boardNUM_SW];

    (void) index; // Solo para evitar el warning del compilador.

    for (i = 0; i < boardNUM_SW; ++i) {
    	HabAlarma[i] = FALSE;
    }

    for (i = 0; i < numParams; ++i) {
        if (strstr(param[i], "contacto1") != (char *)0) {   /* parámetro encontrado */
        	HabAlarma[0] = TRUE;
        }
        if (strstr(param[i], "NA1") != (char *)0) {   /* parámetro encontrado */
        	if (strstr(value[i], "on") != (char *)0){
        		SwNormalAbierto[0] = TRUE;
			}
			else if (strstr(value[i], "off") != (char *)0){
				SwNormalAbierto[0] = FALSE;
			}
        }
        if (strstr(param[i], "contacto2") != (char *)0) {   /* parámetro encontrado */
        	HabAlarma[1] = TRUE;
        }
        if (strstr(param[i], "NA2") != (char *)0) {   /* parámetro encontrado */
        	if (strstr(value[i], "on") != (char *)0){
        		SwNormalAbierto[1] = TRUE;
			}
			else if (strstr(value[i], "off") != (char *)0){
				SwNormalAbierto[1] = FALSE;
			}
        }
        if (strstr(param[i], "contacto3") != (char *)0) {   /* parámetro encontrado */
        	HabAlarma[2] = TRUE;
        }
        if (strstr(param[i], "NA3") != (char *)0) {   /* parámetro encontrado */
        	if (strstr(value[i], "on") != (char *)0){
        		SwNormalAbierto[2] = TRUE;
			}
			else if (strstr(value[i], "off") != (char *)0){
				SwNormalAbierto[2] = FALSE;
			}
        }
        if (strstr(param[i], "contacto4") != (char *)0) {   /* parámetro encontrado */
        	HabAlarma[3] = TRUE;
        }
        if (strstr(param[i], "NA4") != (char *)0) {   /* parámetro encontrado */
        	if (strstr(value[i], "on") != (char *)0){
        		SwNormalAbierto[3] = TRUE;
			}
			else if (strstr(value[i], "off") != (char *)0){
				SwNormalAbierto[3] = FALSE;
			}
        }
        if (strstr(param[i], "contacto5") != (char *)0) {   /* parámetro encontrado */
        	HabAlarma[4] = TRUE;
        }
        if (strstr(param[i], "NA5") != (char *)0) {   /* parámetro encontrado */
        	if (strstr(value[i], "on") != (char *)0){
        		SwNormalAbierto[4] = TRUE;
			}
			else if (strstr(value[i], "off") != (char *)0){
				SwNormalAbierto[4] = FALSE;
			}
        }
        if (strstr(param[i], "contacto6") != (char *)0) {   /* parámetro encontrado */
        	HabAlarma[5] = TRUE;
        }
        if (strstr(param[i], "NA6") != (char *)0) {   /* parámetro encontrado */
        	if (strstr(value[i], "on") != (char *)0){
        		SwNormalAbierto[5] = TRUE;
			}
			else if (strstr(value[i], "off") != (char *)0){
				SwNormalAbierto[5] = FALSE;
			}
        	HabilitarAlarma(45, HabAlarma[i]);
        }
    }

    for (i = 0; i < boardNUM_SW; ++i) {
    	HabilitarAlarma((40+i), HabAlarma[i]);
    }

    return "/contact.ssi";
}

/*********************************************************************//**
 * @brief 		Función para ejecutar al invocar vac.cgi.
 *
 * @param[in]	index Índice dentro de los parámetros de CGI recibidos.
 * @param[in]	numParams Número de parámetros CGI recibidos.
 * @param[in]	*param[] Puntero al vector con los parámetros CGI recibidos.
 * @param[in]	*value[] Puntero al vector con los valores de los parámetros CGI recibidos.
 * @return 		Nombre de la página html que devuelve al finalizar.
 **********************************************************************/
/* TODO: Puede ser que al ingresar valores de umbrales se exeda el largo máx. del string de URL. */
/*       Verificarlo con los valores en la escala adecuada. */
static char const *cgi_vac(int index, int numParams, char *param[], char *value[])
{
    int i, j;
    Bool HabAlm[ 8 ];
    char StringTemp[ 4 ];

    (void) index; // Solo para evitar el warning del compilador.

    for (i = 0; i < 8; ++i) {
    	HabAlm[i] = FALSE;
    }

    for (i = 0; i < numParams; ++i) {
        if (strstr(param[i], "vrmsmax") != (char *)0) {   /* parámetro encontrado */
        	UmbralTensionRMSacMax = (float) atof( value[i] );
        }
        if (strstr(param[i], "vrmsmin") != (char *)0) {   /* parámetro encontrado */
        	UmbralTensionRMSacMin = (float) atof( value[i] );
        }
        if (strstr(param[i], "vppmax") != (char *)0) {   /* parámetro encontrado */
        	UmbralTensionPpAcMax = (float) atof( value[i] );
        }
        if (strstr(param[i], "vpnmax") != (char *)0) {   /* parámetro encontrado */
        	UmbralTensionPnAcMax = (float) atof( value[i] );
        }
        if (strstr(param[i], "vppmin") != (char *)0) {   /* parámetro encontrado */
        	UmbralTensionPpAcMin = (float) atof( value[i] );
        }
        if (strstr(param[i], "vpnmin") != (char *)0) {   /* parámetro encontrado */
        	UmbralTensionPnAcMin = (float) atof( value[i] );
        }
        if (strstr(param[i], "fmax") != (char *)0) {   /* parámetro encontrado */
        	UmbralFrecuenciaMax = (float) atof( value[i] );
        }
        if (strstr(param[i], "fmin") != (char *)0) {   /* parámetro encontrado */
        	UmbralFrecuenciaMin = (float) atof( value[i] );
        }

        for (j = 0; j < 8; ++j) {
        	sprintf((char *)StringTemp, "h%02u", j);
        	if (strstr(param[i], (char *)StringTemp) != (char *)0) {   /* parámetro encontrado */
        		HabAlm[j] = TRUE;
        	}
        }
    }
    for (i = 0; i < 8; ++i) {
    	HabilitarAlarma(i, HabAlm[i]);
    }

    return "/enerac.ssi";
}

/*********************************************************************//**
 * @brief 		Función para ejecutar al invocar aac1.cgi.
 *
 * @param[in]	index Índice dentro de los parámetros de CGI recibidos.
 * @param[in]	numParams Número de parámetros CGI recibidos.
 * @param[in]	*param[] Puntero al vector con los parámetros CGI recibidos.
 * @param[in]	*value[] Puntero al vector con los valores de los parámetros CGI recibidos.
 * @return 		Nombre de la página html que devuelve al finalizar.
 **********************************************************************/
/* TODO: Puede ser que al ingresar valores de umbrales se exeda el largo máx. del string de URL. */
/*       Verificarlo con los valores en la escala adecuada. */
static char const *cgi_aac1(int index, int numParams, char *param[], char *value[])
{
    int i, j;
    Bool HabAlm[ 6 ];
    char StringTemp[ 4 ];

    (void) index; // Solo para evitar el warning del compilador.

    for (i = 0; i < 6; ++i) {
    	HabAlm[i] = FALSE;
    }

    for (i = 0; i < numParams; ++i) {
        if (strstr(param[i], "armsmax") != (char *)0) {   /* parámetro encontrado */
        	UmbralCorrienteRMSac1Max = (float) atof( value[i] );
        }
        if (strstr(param[i], "armsmin") != (char *)0) {   /* parámetro encontrado */
        	UmbralCorrienteRMSac1Min = (float) atof( value[i] );
        }
        if (strstr(param[i], "appmax") != (char *)0) {   /* parámetro encontrado */
        	UmbralCorrientePpAc1Max = (float) atof( value[i] );
        }
        if (strstr(param[i], "apnmax") != (char *)0) {   /* parámetro encontrado */
        	UmbralCorrientePnAc1Max = (float) atof( value[i] );
        }
        if (strstr(param[i], "appmin") != (char *)0) {   /* parámetro encontrado */
        	UmbralCorrientePpAc1Min = (float) atof( value[i] );
        }
        if (strstr(param[i], "apnmin") != (char *)0) {   /* parámetro encontrado */
        	UmbralCorrientePnAc1Min = (float) atof( value[i] );
        }

        for (j = 0; j < 6; ++j) {
        	sprintf((char *)StringTemp, "h%02u", j);
        	if (strstr(param[i], (char *)StringTemp) != (char *)0) {   /* parámetro encontrado */
        		HabAlm[j] = TRUE;
        	}
        }
    }
    for (i = 0; i < 6; ++i) {
    	HabilitarAlarma(i+8, HabAlm[i]);
    }

    return "/enerac.ssi";
}

/*********************************************************************//**
 * @brief 		Función para ejecutar al invocar aac2.cgi.
 *
 * @param[in]	index Índice dentro de los parámetros de CGI recibidos.
 * @param[in]	numParams Número de parámetros CGI recibidos.
 * @param[in]	*param[] Puntero al vector con los parámetros CGI recibidos.
 * @param[in]	*value[] Puntero al vector con los valores de los parámetros CGI recibidos.
 * @return 		Nombre de la página html que devuelve al finalizar.
 **********************************************************************/
/* TODO: Puede ser que al ingresar valores de umbrales se exeda el largo máx. del string de URL. */
/*       Verificarlo con los valores en la escala adecuada. */
static char const *cgi_aac2(int index, int numParams, char *param[], char *value[])
{
    int i, j;
    Bool HabAlm[ 6 ];
    char StringTemp[ 4 ];

    (void) index; // Solo para evitar el warning del compilador.

    for (i = 0; i < 6; ++i) {
    	HabAlm[i] = FALSE;
    }

    for (i = 0; i < numParams; ++i) {
        if (strstr(param[i], "armsmax") != (char *)0) {   /* parámetro encontrado */
        	UmbralCorrienteRMSac2Max = (float) atof( value[i] );
        }
        if (strstr(param[i], "armsmin") != (char *)0) {   /* parámetro encontrado */
        	UmbralCorrienteRMSac2Min = (float) atof( value[i] );
        }
        if (strstr(param[i], "appmax") != (char *)0) {   /* parámetro encontrado */
        	UmbralCorrientePpAc2Max = (float) atof( value[i] );
        }
        if (strstr(param[i], "apnmax") != (char *)0) {   /* parámetro encontrado */
        	UmbralCorrientePnAc2Max = (float) atof( value[i] );
        }
        if (strstr(param[i], "appmin") != (char *)0) {   /* parámetro encontrado */
        	UmbralCorrientePpAc2Min = (float) atof( value[i] );
        }
        if (strstr(param[i], "apnmin") != (char *)0) {   /* parámetro encontrado */
        	UmbralCorrientePnAc2Min = (float) atof( value[i] );
        }

        for (j = 0; j < 6; ++j) {
        	sprintf((char *)StringTemp, "h%02u", j);
        	if (strstr(param[i], (char *)StringTemp) != (char *)0) {   /* parámetro encontrado */
        		HabAlm[j] = TRUE;
        	}
        }
    }
    for (i = 0; i < 6; ++i) {
    	HabilitarAlarma(i+17, HabAlm[i]);
    }

    return "/enerac.ssi";
}

/*********************************************************************//**
 * @brief 		Función para ejecutar al invocar vdc.cgi.
 *
 * @param[in]	index Índice dentro de los parámetros de CGI recibidos.
 * @param[in]	numParams Número de parámetros CGI recibidos.
 * @param[in]	*param[] Puntero al vector con los parámetros CGI recibidos.
 * @param[in]	*value[] Puntero al vector con los valores de los parámetros CGI recibidos.
 * @return 		Nombre de la página html que devuelve al finalizar.
 **********************************************************************/
/* TODO: Puede ser que al ingresar valores de umbrales se exeda el largo máx. del string de URL. */
/*       Verificarlo con los valores en la escala adecuada. */
static char const *cgi_vdc(int index, int numParams, char *param[], char *value[])
{
    int i, j;
    Bool HabAlm[ 2 ];
    char StringTemp[ 4 ];

    (void) index; // Solo para evitar el warning del compilador.

    for (i = 0; i < 2; ++i) {
    	HabAlm[i] = FALSE;
    }

    for (i = 0; i < numParams; ++i) {
        if (strstr(param[i], "vdcmax") != (char *)0) {   /* parámetro encontrado */
        	UmbralTensionDCMax = (float) atof( value[i] );
        }
        if (strstr(param[i], "vdcmin") != (char *)0) {   /* parámetro encontrado */
        	UmbralTensionDCMin = (float) atof( value[i] );
        }

        for (j = 0; j < 2; ++j) {
        	sprintf((char *)StringTemp, "h%02u", j);
        	if (strstr(param[i], (char *)StringTemp) != (char *)0) {   /* parámetro encontrado */
        		HabAlm[j] = TRUE;
        	}
        }
    }
    for (i = 0; i < 2; ++i) {
    	HabilitarAlarma(i+24, HabAlm[i]);
    }

    return "/enerdc.ssi";
}

/*********************************************************************//**
 * @brief 		Función para ejecutar al invocar adc1.cgi.
 *
 * @param[in]	index Índice dentro de los parámetros de CGI recibidos.
 * @param[in]	numParams Número de parámetros CGI recibidos.
 * @param[in]	*param[] Puntero al vector con los parámetros CGI recibidos.
 * @param[in]	*value[] Puntero al vector con los valores de los parámetros CGI recibidos.
 * @return 		Nombre de la página html que devuelve al finalizar.
 **********************************************************************/
/* TODO: Puede ser que al ingresar valores de umbrales se exeda el largo máx. del string de URL. */
/*       Verificarlo con los valores en la escala adecuada. */
static char const *cgi_adc1(int index, int numParams, char *param[], char *value[])
{
    int i, j;
    Bool HabAlm[ 2 ];
    char StringTemp[ 4 ];

    (void) index; // Solo para evitar el warning del compilador.

    for (i = 0; i < 2; ++i) {
    	HabAlm[i] = FALSE;
    }

    for (i = 0; i < numParams; ++i) {
        if (strstr(param[i], "adcmax") != (char *)0) {   /* parámetro encontrado */
        	UmbralCorrienteDC1Max = (float) atof( value[i] );
        }
        if (strstr(param[i], "adcmin") != (char *)0) {   /* parámetro encontrado */
        	UmbralCorrienteDC1Min = (float) atof( value[i] );
        }

        for (j = 0; j < 2; ++j) {
        	sprintf((char *)StringTemp, "h%02u", j);
        	if (strstr(param[i], (char *)StringTemp) != (char *)0) {   /* parámetro encontrado */
        		HabAlm[j] = TRUE;
        	}
        }
    }
    for (i = 0; i < 2; ++i) {
    	HabilitarAlarma(i+26, HabAlm[i]);
    }

    return "/enerdc.ssi";
}

/*********************************************************************//**
 * @brief 		Función para ejecutar al invocar adc2.cgi.
 *
 * @param[in]	index Índice dentro de los parámetros de CGI recibidos.
 * @param[in]	numParams Número de parámetros CGI recibidos.
 * @param[in]	*param[] Puntero al vector con los parámetros CGI recibidos.
 * @param[in]	*value[] Puntero al vector con los valores de los parámetros CGI recibidos.
 * @return 		Nombre de la página html que devuelve al finalizar.
 **********************************************************************/
/* TODO: Puede ser que al ingresar valores de umbrales se exeda el largo máx. del string de URL. */
/*       Verificarlo con los valores en la escala adecuada. */
static char const *cgi_adc2(int index, int numParams, char *param[], char *value[])
{
    int i, j;
    Bool HabAlm[ 2 ];
    char StringTemp[ 4 ];

    (void) index; // Solo para evitar el warning del compilador.

    for (i = 0; i < 2; ++i) {
    	HabAlm[i] = FALSE;
    }

    for (i = 0; i < numParams; ++i) {
        if (strstr(param[i], "adcmax") != (char *)0) {   /* parámetro encontrado */
        	UmbralCorrienteDC2Max = (float) atof( value[i] );
        }
        if (strstr(param[i], "adcmin") != (char *)0) {   /* parámetro encontrado */
        	UmbralCorrienteDC2Min = (float) atof( value[i] );
        }

        for (j = 0; j < 2; ++j) {
        	sprintf((char *)StringTemp, "h%02u", j);
        	if (strstr(param[i], (char *)StringTemp) != (char *)0) {   /* parámetro encontrado */
        		HabAlm[j] = TRUE;
        	}
        }
    }
    for (i = 0; i < 2; ++i) {
    	HabilitarAlarma(i+29, HabAlm[i]);
    }

    return "/enerdc.ssi";
}

/*********************************************************************//**
 * @brief 		Función para ejecutar al invocar histo.cgi.
 *
 * @param[in]	index Índice dentro de los parámetros de CGI recibidos.
 * @param[in]	numParams Número de parámetros CGI recibidos.
 * @param[in]	*param[] Puntero al vector con los parámetros CGI recibidos.
 * @param[in]	*value[] Puntero al vector con los valores de los parámetros CGI recibidos.
 * @return 		Nombre de la página html que devuelve al finalizar.
 **********************************************************************/
static char const *cgi_histo(int index, int numParams, char *param[], char *value[])
{
    int i;
    uint8_t Retorno = 0;

    (void) index; // Solo para evitar el warning del compilador.

    for (i = 0; i < numParams; ++i) {
        if (strstr(param[i], "dia") != (char *)0) {   /* parámetro encontrado */
        	FechaLog[0] = atoi(value[i]);
		}
        if (strstr(param[i], "mes") != (char *)0) {   /* parámetro encontrado */
        	FechaLog[1] = atoi(value[i]);
		}
        if (strstr(param[i], "anio") != (char *)0) {   /* parámetro encontrado */
        	FechaLog[2] = atoi(value[i]);
		}
        if (strstr(param[i], "origen") != (char *)0) {   /* parámetro encontrado */
			if (strcmp(value[i], "enerac") == 0) {
				Retorno = 1;
			}
			else if (strcmp(value[i], "enerdc") == 0) {
				Retorno = 2;
			}
			else if (strcmp(value[i], "ambie") == 0) {
				Retorno = 3;
			}
		}
    }
    switch (Retorno){
    case 1:
    	return "/enerac.ssi";
    	break;

    case 2:
		return "/enerdc.ssi";
		break;

    case 3:
		return "/ambiente.ssi";
		break;

     default:
    	return (char *)0;/*si no se encuentra el URI, HTTPD envía error 404*/
    }
}

/*********************************************************************//**
 * @brief 		Función para insertar el archivo de log de mediciones de temperatura.
 *
 * @param[out]	*pcWriteBuffer Puntero del buffer donde se escribe el texto generado.
 * @return 		None
 **********************************************************************/
void prvInsertarLogTemperatura( signed char *pcWriteBuffer )
{
	*pcWriteBuffer = ( signed char ) 0x00;
	sprintf( (char *)pcWriteBuffer, "<object width=\"50%%\" height=\"280\" type=\"text/plain\" data=\"te%02u%02u%02u.txt\" border=\"0\"></object>", FechaLog[0], FechaLog[1], FechaLog[2]);
}

/*********************************************************************//**
 * @brief 		Función para insertar el archivo de log de mediciones de energía AC.
 *
 * @param[out]	*pcWriteBuffer Puntero del buffer donde se escribe el texto generado.
 * @return 		None
 **********************************************************************/
void prvInsertarLogEnergiaAC( signed char *pcWriteBuffer )
{
	*pcWriteBuffer = ( signed char ) 0x00;
	sprintf( (char *)pcWriteBuffer, "<object width=\"100%%\" height=\"280\" type=\"text/plain\" data=\"ac%02u%02u%02u.txt\" border=\"0\"></object>", FechaLog[0], FechaLog[1], FechaLog[2]);
}

/*********************************************************************//**
 * @brief 		Función para insertar el archivo de log de mediciones de energía DC.
 *
 * @param[out]	*pcWriteBuffer Puntero del buffer donde se escribe el texto generado.
 * @return 		None
 **********************************************************************/
void prvInsertarLogEnergiaDC( signed char *pcWriteBuffer )
{
	*pcWriteBuffer = ( signed char ) 0x00;
	sprintf( (char *)pcWriteBuffer, "<object width=\"100%%\" height=\"280\" type=\"text/plain\" data=\"dc%02u%02u%02u.txt\" border=\"0\"></object>", FechaLog[0], FechaLog[1], FechaLog[2]);
}

/*********************************************************************//**
 * @brief 		Función para enviar las direcciones IP.
 *
 * @param[out]	*pcWriteBuffer Puntero del buffer donde se escribe el texto generado.
 * @return 		None
 **********************************************************************/
void prvInsertarDireccionesIP( signed char *pcWriteBuffer )
{
	*pcWriteBuffer = ( signed char ) 0x00;
	sprintf( (char *) pcWriteBuffer, "Dirección: <input type=\"text\" name=\"addr1\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">.<input type=\"text\" name=\"addr2\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">.<input type=\"text\" name=\"addr3\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">.<input type=\"text\" name=\"addr4\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\"><br>", configIP_ADDR[0], configIP_ADDR[1], configIP_ADDR[2], configIP_ADDR[3] );
	sprintf( ((char *)pcWriteBuffer)+(strlen((const char *)pcWriteBuffer)), "Máscara: &nbsp;&nbsp;<input type=\"text\" name=\"mask1\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">.<input type=\"text\" name=\"mask2\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">.<input type=\"text\" name=\"mask3\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">.<input type=\"text\" name=\"mask4\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\"><br>", configNET_MASK[0], configNET_MASK[1], configNET_MASK[2], configNET_MASK[3] );
	sprintf( ((char *)pcWriteBuffer)+(strlen((const char *)pcWriteBuffer)), "Gateway: &nbsp;&nbsp;<input type=\"text\" name=\"gway1\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">.<input type=\"text\" name=\"gway2\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">.<input type=\"text\" name=\"gway3\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">.<input type=\"text\" name=\"gway4\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">", configGW_IP_ADDR[0], configGW_IP_ADDR[1], configGW_IP_ADDR[2], configGW_IP_ADDR[3] );
}

/*********************************************************************//**
 * @brief 		Función para ejecutar al invocar ipaddr.cgi.
 *
 * @param[in]	index Índice dentro de los parámetros de CGI recibidos.
 * @param[in]	numParams Número de parámetros CGI recibidos.
 * @param[in]	*param[] Puntero al vector con los parámetros CGI recibidos.
 * @param[in]	*value[] Puntero al vector con los valores de los parámetros CGI recibidos.
 * @return 		Nombre de la página html que devuelve al finalizar.
 **********************************************************************/
static char const *cgi_ipaddr(int index, int numParams, char *param[], char *value[])
{
	uint32_t i = 0;
	uint32_t j = 0;
	char cTempString[ 6 ];
	int32_t DatoTemporal;
	struct ip_addr ipTemp;

	(void) index;     // Solo para evitar el warning del compilador.
	(void) numParams; // Solo para evitar el warning del compilador.

	for (i = 0; i < 4; i++){
		sprintf((char *)cTempString, "addr%u", i+1);
		if (strstr(param[i], (char *)cTempString) != (char *)0) {   /* parámetro encontrado */
			DatoTemporal = atoi(value[i]);
			if ((DatoTemporal >= 0) && (DatoTemporal <= 255)){
				configIP_ADDR[i] = DatoTemporal;
				j++;
			}
		}
	}
	if (j == 4){
		IP4_ADDR(&ipTemp, configIP_ADDR[0], configIP_ADDR[1], configIP_ADDR[2], configIP_ADDR[3]);
		netif_set_ipaddr(&xNetIf, &ipTemp); // Cambiar la dirección IP.
	}

	for (i = 0; i < 4; i++){
		sprintf((char *)cTempString, "mask%u", i+1);
		if (strstr(param[i+4], (char *)cTempString) != (char *)0) {   /* parámetro encontrado */
			DatoTemporal = atoi(value[i+4]);
			if ((DatoTemporal >= 0) && (DatoTemporal <= 255)){
				configNET_MASK[i] = DatoTemporal;
				j++;
			}
		}
	}
	if (j == 8){
		IP4_ADDR(&ipTemp, configNET_MASK[0], configNET_MASK[1], configNET_MASK[2], configNET_MASK[3]);
		netif_set_netmask(&xNetIf, &ipTemp); // Cambiar la Máscara.
	}

	for (i = 0; i < 4; i++){
		sprintf((char *)cTempString, "gway%u", i+1);
		if (strstr(param[i+8], (char *)cTempString) != (char *)0) {   /* parámetro encontrado */
			DatoTemporal = atoi(value[i+8]);
			if ((DatoTemporal >= 0) && (DatoTemporal <= 255)){
				configGW_IP_ADDR[i] = DatoTemporal;
				j++;
			}
		}
	}
	if (j == 12){
		IP4_ADDR(&ipTemp, configGW_IP_ADDR[0], configGW_IP_ADDR[1], configGW_IP_ADDR[2], configGW_IP_ADDR[3]);
		netif_set_gw(&xNetIf, &ipTemp); // Cambiar el Default Gateway.
	}

	if (j==12){
		return "/sistema.ssi";
	}
	else {
		return (char *)0;/*si no se encuentra el URI, HTTPD envía error 404*/
	}
}

/*********************************************************************//**
 * @brief 		Función para enviar las direcciones IP de SNTP.
 *
 * @param[out]	*pcWriteBuffer Puntero del buffer donde se escribe el texto generado.
 * @return 		None
 **********************************************************************/
void prvInsertarDireccionesSNTP( signed char *pcWriteBuffer )
{
	uint8_t i = 0;
	uint8_t dir1[ 4 ] = {0,0,0,0};
	uint8_t dir2[ 4 ] = {0,0,0,0};
	ip_addr_t Direccion;

	i = ipaddr_aton(&sntp_direccion1[0], &Direccion);
	if (i != 0){
		dir1[3] = (Direccion.addr >> 24);
		dir1[2] = (Direccion.addr >> 16) & 0xFF;
		dir1[1] = (Direccion.addr >>  8) & 0xFF;
		dir1[0] = (Direccion.addr      ) & 0xFF;
	}

	i = ipaddr_aton(&sntp_direccion2[0], &Direccion);
	if (i != 0){
		dir2[3] = (Direccion.addr >> 24);
		dir2[2] = (Direccion.addr >> 16) & 0xFF;
		dir2[1] = (Direccion.addr >>  8) & 0xFF;
		dir2[0] = (Direccion.addr      ) & 0xFF;
	}


	*pcWriteBuffer = ( signed char ) 0x00;
	sprintf( (char *)pcWriteBuffer, "Servidor 1: <input type=\"text\" name=\"ntp11\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">.<input type=\"text\" name=\"ntp12\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">.<input type=\"text\" name=\"ntp13\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">.<input type=\"text\" name=\"ntp14\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\"><br>", dir1[0], dir1[1], dir1[2], dir1[3] );
	sprintf( ((char *)pcWriteBuffer)+(strlen((const char *)pcWriteBuffer)), "Servidor 2: <input type=\"text\" name=\"ntp21\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">.<input type=\"text\" name=\"ntp22\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">.<input type=\"text\" name=\"ntp23\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">.<input type=\"text\" name=\"ntp24\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\"><br>", dir2[0], dir2[1], dir2[2], dir2[3] );
	sprintf( ((char *)pcWriteBuffer)+(strlen((const char *)pcWriteBuffer)),"Zona horaria UTC: <input type=\"text\" name=\"zh\" size=\"3\" maxlength=\"3\" value=\"%d\" style=\"font-family: Consolas;\">[horas]", ZhOffset );
}

/*********************************************************************//**
 * @brief 		Función para enviar la dirección IP de SysLog.
 *
 * @param[out]	*pcWriteBuffer Puntero del buffer donde se escribe el texto generado.
 * @return 		None
 **********************************************************************/
void prvInsertarDireccionSL( signed char *pcWriteBuffer )
{
	uint8_t dir[ 4 ] = {0,0,0,0};

	*pcWriteBuffer = ( signed char ) 0x00;
	dir[3] = (DireccionSLServer.addr >> 24);
	dir[2] = (DireccionSLServer.addr >> 16) & 0xFF;
	dir[1] = (DireccionSLServer.addr >>  8) & 0xFF;
	dir[0] = (DireccionSLServer.addr      ) & 0xFF;

	sprintf( (char *)pcWriteBuffer, "Servidor: <input type=\"text\" name=\"sl1\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">.<input type=\"text\" name=\"sl2\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">.<input type=\"text\" name=\"sl3\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\">.<input type=\"text\" name=\"sl4\" size=\"3\" maxlength=\"3\" value=\"%u\" style=\"font-family: Consolas;\"><br>", dir[0], dir[1], dir[2], dir[3] );
}

/*********************************************************************//**
 * @brief 		Función para ejecutar al invocar ipsntp.cgi.
 *
 * @param[in]	index Índice dentro de los parámetros de CGI recibidos.
 * @param[in]	numParams Número de parámetros CGI recibidos.
 * @param[in]	*param[] Puntero al vector con los parámetros CGI recibidos.
 * @param[in]	*value[] Puntero al vector con los valores de los parámetros CGI recibidos.
 * @return 		Nombre de la página html que devuelve al finalizar.
 **********************************************************************/
/* TODO: Forzar actualización de SNTP al recibir parámetros. */
static char const *cgi_ipsntp(int index, int numParams, char *param[], char *value[])
{
	uint8_t i = 0;
	uint8_t j = 0;
	char cTempString[ 6 ];
	int32_t DatoTemporal[ 4 ];

	(void) index;     // Solo para evitar el warning del compilador.
	(void) numParams; // Solo para evitar el warning del compilador.

	for (i = 0; i < 4; i++){
		sprintf((char *)cTempString, "ntp1%u", i+1);
		if (strstr(param[i], (char *)cTempString) != (char *)0) {   /* parámetro encontrado */
			DatoTemporal[i] = atoi(value[i]);
			if ((DatoTemporal[i] >= 0) && (DatoTemporal[i] <= 255)){
				j++;
			}
		}
	}
	if (j == 4){
		sprintf((char *)sntp_direccion1, "%u.%u.%u.%u", DatoTemporal[0], DatoTemporal[1], DatoTemporal[2], DatoTemporal[3]);
	}
	for (i = 0; i < 4; i++){
		sprintf((char *)cTempString, "ntp2%u", i+1);
		if (strstr(param[i+4], (char *)cTempString) != (char *)0) {   /* parámetro encontrado */
			DatoTemporal[i] = atoi(value[i+4]);
			if ((DatoTemporal[i] >= 0) && (DatoTemporal[i] <= 255)){

				j++;
			}
		}
	}
	if (j == 8){
		sprintf((char *)sntp_direccion2, "%u.%u.%u.%u", DatoTemporal[0], DatoTemporal[1], DatoTemporal[2], DatoTemporal[3]);
	}
	if (strstr(param[8], "zh") != (char *)0) {   /* parámetro encontrado */
		ZhOffset = atoi(value[8]);
		j++;
	}

	if (j == 9){
		return "/sistema.ssi";
	}
	else {
		return (char *)0;/*si no se encuentra el URI, HTTPD envía error 404*/
	}
}

/*********************************************************************//**
 * @brief 		Función para ejecutar al invocar ipsl.cgi.
 *
 * @param[in]	index Índice dentro de los parámetros de CGI recibidos.
 * @param[in]	numParams Número de parámetros CGI recibidos.
 * @param[in]	*param[] Puntero al vector con los parámetros CGI recibidos.
 * @param[in]	*value[] Puntero al vector con los valores de los parámetros CGI recibidos.
 * @return 		Nombre de la página html que devuelve al finalizar.
 **********************************************************************/
static char const *cgi_ipsl(int index, int numParams, char *param[], char *value[])
{
	uint8_t i = 0;
	uint8_t j = 0;
	char cTempString[ 16 ];
	int32_t DatoTemporal[ 4 ];
	ip_addr_t Direccion;

	(void) index;     // Solo para evitar el warning del compilador.
	(void) numParams; // Solo para evitar el warning del compilador.

	for (i = 0; i < 4; i++){
		sprintf((char *)cTempString, "sl%u", i+1);
		if (strstr(param[i], (char *)cTempString) != (char *)0) {   /* parámetro encontrado */
			DatoTemporal[i] = atoi(value[i]);
			if ((DatoTemporal[i] >= 0) && (DatoTemporal[i] <= 255)){
				j++;
			}
		}
	}
	if (j == 4){
		sprintf((char *)cTempString, "%u.%u.%u.%u", DatoTemporal[0], DatoTemporal[1], DatoTemporal[2], DatoTemporal[3]);
		i = ipaddr_aton(&cTempString[0], &Direccion);
		if (i != 0){
			DireccionSLServer = Direccion;
		}
		return "/sistema.ssi";
	}

	return (char *)0;/*si no se encuentra el URI, HTTPD envía error 404*/

}

/*********************************************************************//**
 * @brief 		Función para ejecutar al invocar guardar.cgi.
 *
 * @param[in]	index Índice dentro de los parámetros de CGI recibidos.
 * @param[in]	numParams Número de parámetros CGI recibidos.
 * @param[in]	*param[] Puntero al vector con los parámetros CGI recibidos.
 * @param[in]	*value[] Puntero al vector con los valores de los parámetros CGI recibidos.
 * @return 		Nombre de la página html que devuelve al finalizar.
 **********************************************************************/
static char const *cgi_guardar(int index, int numParams, char *param[], char *value[])
{
	(void) index;     // Solo para evitar el warning del compilador.
	(void) numParams; // Solo para evitar el warning del compilador.

	if ((strstr(param[0], "guardar") != (char *)0) && (strstr(value[0], "ya") != (char *)0)) {   /* parámetro encontrado */
		WriteSDConfig();  // Guardar el archivo de configuración config.txt
		return "/sistema.ssi";
	}
	else {
		return (char *)0;/*si no se encuentra el URI, HTTPD envía error 404*/
	}
}

static char const *cgi_wdhab(int index, int numParams, char *param[], char *value[])
{
    int i, j;
    Bool HabAlm[] = {FALSE, FALSE, FALSE, FALSE};
    Bool HabPng[] = {FALSE, FALSE, FALSE, FALSE};
    char StringTemp[ 7 ];

    (void) index; // Solo para evitar el warning del compilador.

    for (i = 0; i < 4; ++i) {
    	sprintf((char *)StringTemp, "wdhab%u", i+1);
    	for (j = 0; j < numParams; ++j) {
			if (strstr(param[j], (char *)StringTemp) != (char *)0) {   /* parámetro encontrado */
				HabPng[i] = TRUE;
			}
    	}
        sprintf((char *)StringTemp, "wdalm%u", i+1);
    	for (j = 0; j < numParams; ++j) {
			if (strstr(param[j], (char *)StringTemp) != (char *)0) {   /* parámetro encontrado */
				HabAlm[i] = TRUE;
			}
    	}
    }
    for (i = 0; i < 4; ++i) {
    	HabilitaPing[i] = HabPng[i];
    	HabilitarAlarma(NumAlarmaWD[i], HabAlm[i]);
    }

    return "/watchdog.ssi";
}
/*********************************************************************//**
 * @brief 		Función para ejecutar al invocar wdip.cgi.
 *
 * @param[in]	index Índice dentro de los parámetros de CGI recibidos.
 * @param[in]	numParams Número de parámetros CGI recibidos.
 * @param[in]	*param[] Puntero al vector con los parámetros CGI recibidos.
 * @param[in]	*value[] Puntero al vector con los valores de los parámetros CGI recibidos.
 * @return 		Nombre de la página html que devuelve al finalizar.
 **********************************************************************/
static char const *cgi_wdip(int index, int numParams, char *param[], char *value[])
{
	uint8_t i = 0;
	uint8_t j = 0;
	uint8_t k = 0;
	char cTempString[ 16 ];
	int32_t DatoTemporal[ 4 ];
	ip_addr_t Direccion;

	(void) index;     // Solo para evitar el warning del compilador.
	(void) numParams; // Solo para evitar el warning del compilador.

	for (k = 0; i < 4; k++){
		for (i = 0; i < 4; i++){
			sprintf((char *)cTempString, "ip%u%u", k+1, i+1);
			if (strstr(param[i+(4*k)], (char *)cTempString) != (char *)0) {   /* parámetro encontrado */
				DatoTemporal[i] = atoi(value[i+(4*k)]);
				if ((DatoTemporal[i] >= 0) && (DatoTemporal[i] <= 255)){
					j++;
				}
			}
		}
		if (j == 4*(k+1)){
			sprintf((char *)cTempString, "%u.%u.%u.%u", DatoTemporal[0], DatoTemporal[1], DatoTemporal[2], DatoTemporal[3]);
			i = ipaddr_aton(&cTempString[0], &Direccion);
			if (i != 0){
				DireccionPing[k] = Direccion;
			}
		}
	}

	if (j == 16){
		return "/watchdog.ssi";
	}
	else {
		return (char *)0;/*si no se encuentra el URI, HTTPD envía error 404*/
	}
}

/*********************************************************************//**
 * @brief 		Función para ejecutar al invocar wdtime.cgi.
 *
 * @param[in]	index Índice dentro de los parámetros de CGI recibidos.
 * @param[in]	numParams Número de parámetros CGI recibidos.
 * @param[in]	*param[] Puntero al vector con los parámetros CGI recibidos.
 * @param[in]	*value[] Puntero al vector con los valores de los parámetros CGI recibidos.
 * @return 		Nombre de la página html que devuelve al finalizar.
 **********************************************************************/
/* TODO: Validar parámetros de entrada. */
static char const *cgi_wdtime(int index, int numParams, char *param[], char *value[])
{
    int i;

    (void) index; // Solo para evitar el warning del compilador.

    for (i = 0; i < numParams; ++i) {
    	if (strstr(param[i], "pingu") != (char *)0) {   /* parámetro encontrado */
    		UmbralPing = (uint8_t) atoi(value[i]);
        }
    	if (strstr(param[i], "pingt") != (char *)0) {   /* parámetro encontrado */
    		DeltaP = (uint16_t) atoi(value[i]);
        }
    	if (strstr(param[i], "toff") != (char *)0) {   /* parámetro encontrado */
    		DeltaOff = (uint16_t) atoi(value[i]);
        }
    }

    return "/watchdog.ssi";
}

/**
 * @}
 */

/* --------------------------------- End Of File ------------------------------ */
