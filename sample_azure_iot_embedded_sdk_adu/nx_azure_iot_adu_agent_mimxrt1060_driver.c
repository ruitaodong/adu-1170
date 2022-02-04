/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
/**************************************************************************/

#include "nx_azure_iot_adu_agent.h"
#include "flash_info.h"
#include "sbl_ota_flag.h"

static uint32_t dstAddr;

void nx_azure_iot_adu_agent_driver(NX_AZURE_IOT_ADU_AGENT_DRIVER *driver_req_ptr);

/****** DRIVER SPECIFIC ******/
void nx_azure_iot_adu_agent_driver(NX_AZURE_IOT_ADU_AGENT_DRIVER *driver_req_ptr)
{
    status_t status;
    volatile uint32_t primask;

    /* Default to successful return.  */
    driver_req_ptr -> nx_azure_iot_adu_agent_driver_status = NX_AZURE_IOT_SUCCESS;
        
    /* Process according to the driver request type.  */
    switch (driver_req_ptr -> nx_azure_iot_adu_agent_driver_command)
    {
        
        case NX_AZURE_IOT_ADU_AGENT_DRIVER_INITIALIZE:
        {
            /* To make the last update fully effective */
            write_image_ok();
           
            /* Process initialize requests.  */       
            uint8_t image_position;
            
            sfw_flash_read(REMAP_FLAG_ADDRESS, &image_position, 1);
            if(image_position == 0x01)
            {
                dstAddr = FLASH_AREA_IMAGE_2_OFFSET;
            }
            else if(image_position == 0x02)
            {
                dstAddr = FLASH_AREA_IMAGE_1_OFFSET;        
            }
      
            break;
        }
            
        case NX_AZURE_IOT_ADU_AGENT_DRIVER_PREPROCESS:
        {
        
            /* Process firmware preprocess requests before writing firmware.
               Such as: erase the flash at once to improve the speed.  */
            uint32_t sec_num = 0;
            if((driver_req_ptr->nx_azure_iot_adu_agent_driver_firmware_size) % FLASH_AREA_IMAGE_SECTOR_SIZE)
            {
                sec_num = (uint32_t)(driver_req_ptr->nx_azure_iot_adu_agent_driver_firmware_size / FLASH_AREA_IMAGE_SECTOR_SIZE) + 1;
            }
            else
            {
                sec_num = (uint32_t)(driver_req_ptr->nx_azure_iot_adu_agent_driver_firmware_size / FLASH_AREA_IMAGE_SECTOR_SIZE);
            }
            
            primask = DisableGlobalIRQ();
            status = sfw_flash_erase(dstAddr, sec_num * FLASH_AREA_IMAGE_SECTOR_SIZE);
            EnableGlobalIRQ(primask);
            
            break;
        }
            
        case NX_AZURE_IOT_ADU_AGENT_DRIVER_WRITE:
        {
        
            /* Process firmware write requests.  */
            
            /* Write firmware contents.
               1. This function must support figure out which bank it should write to.
               2. Write firmware contents into new bank.
               3. Decrypt and authenticate the firmware itself if needed.
            */
            primask = DisableGlobalIRQ();
            status = sfw_flash_write(dstAddr + driver_req_ptr->nx_azure_iot_adu_agent_driver_firmware_data_offset,
                                     (uint32_t *)(driver_req_ptr->nx_azure_iot_adu_agent_driver_firmware_data_ptr),
                                     driver_req_ptr->nx_azure_iot_adu_agent_driver_firmware_data_size);
            if (status) 
            {
                return;
            }
            EnableGlobalIRQ(primask);
            
            break;
        } 
            
        case NX_AZURE_IOT_ADU_AGENT_DRIVER_INSTALL:
        {

            /* Set the new firmware for next boot.  */
            enable_image();
            
            break;
        } 
            
        case NX_AZURE_IOT_ADU_AGENT_DRIVER_APPLY:
        {

            /* Apply the new firmware, and reboot device from that.*/
            NVIC_SystemReset();
            
            break;
        } 
        default:
        {
                
            /* Invalid driver request.  */

            /* Default to successful return.  */
            driver_req_ptr -> nx_azure_iot_adu_agent_driver_status =  NX_AZURE_IOT_FAILURE;
        }
    }
}
