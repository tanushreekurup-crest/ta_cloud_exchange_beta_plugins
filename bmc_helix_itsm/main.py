"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

BMC Helix ITSM Plugin.
"""

import traceback
import json
import ipaddress
import re
from typing import List, Dict
from .utils.bmc_helix_exceptions import (
    BMCHelixPluginException,
)
from .utils.bmc_helix_api_helper import (
    BMCHelixPluginHelper,
)
from .utils.bmc_helix_constants import (
    PLATFORM_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
    LOGIN_URL,
    TASK_URL,
    INCIDENT_SERVICE_TYPE_MAPPING,
    URGENCY_MAPPING,
    IMPACT_MAPPING,
    INCIDENT_TYPES,
    URGENCY,
    IMPACT,
    GET_TASK_URL,
)

from netskope.integrations.itsm.plugin_base import (
    PluginBase,
    ValidationResult,
    MappingField,
)

from netskope.integrations.itsm.models import (
    FieldMapping,
    Queue,
    Task,
    TaskStatus,
    Alert,
)

STATE_MAPPINGS = {
    "New": TaskStatus.NEW,
    "In Progress": TaskStatus.IN_PROGRESS,
    "Pending": TaskStatus.ON_HOLD,
    "Closed": TaskStatus.CLOSED,
}


class BMCHelixPlugin(PluginBase):
    """BMCHelixPlugin Plugin class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize BMCHelixPlugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"
        self.bmc_helix_helper = BMCHelixPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.
        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = BMCHelixPlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _is_valid_ipv4(self, address: str) -> bool:
        """Validate IPv4 address.

        Args:
            address (str): Address to validate.

        Returns:
            bool: True if valid else False.
        """
        try:
            ipaddress.IPv4Address(address)
            return True
        except Exception:
            return False

    def _is_valid_host(self, value: str) -> bool:
        """Validate host name.

        Args:
            value (str): Host name.

        Returns:
            bool: Whether the name is valid or not.
        """
        try:
            host_regex = r"^(?:[a-zA-Z]*:\/\/)?([\w\-\.]+)(?:\/)?"
            if re.match(host_regex, value):
                return True
            else:
                return False
        except Exception:
            return False

    def validate_step(
        self, name: str, configuration: dict
    ) -> ValidationResult:
        """Validate a given configuration step."""
        if name == "auth":
            return self._validate_auth(configuration)
        elif name == "params":
            return self._validate_params(configuration)
        else:
            return ValidationResult(
                success=True, message="Validation successful."
            )

    def _validate_auth(self, configuration):
        """Validate the Plugin authentication parameters."""
        auth_params = configuration.get("auth", {})

        validation_err_msg = f"{self.log_prefix}: Validation error occurred."

        servername = auth_params.get("servername").strip()
        if not servername:
            err_msg = "Server Name is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(servername, str):
            err_msg = "Invalid Server Name provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif (not self._is_valid_ipv4(servername)) or (not self._is_valid_host(servername)):
            err_msg = "Invalid Server Name provided in configuration parameters. Please provide a valid Server Name."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        port = auth_params.get("port")
        if not port:
            err_msg = "Port is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(port, int):
            err_msg = "Invalid Port provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif port <= 0 or port > 65535:
            err_msg = "Invalid Port provided in configuration parameters. Port should be between 1 and 65535."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        username = auth_params.get("username").strip()
        if not username:
            err_msg = "Username is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(username, str):
            err_msg = "Invalid Username provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        password = auth_params.get("password")
        if not password:
            err_msg = "Password is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(password, str):
            err_msg = "Invalid Password provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self.validate_auth_params(configuration, validation_err_msg)

    def _validate_params(self, configuration):
        """Validate the Plugin parameters."""
        params = configuration.get("params", {})

        validation_err_msg = f"{self.log_prefix}: Validation error occurred."

        first_name = params.get("first_name").strip()
        if not first_name:
            err_msg = "First Name is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if not isinstance(first_name, str):
            err_msg = "Invalid First Name provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        last_name = params.get("last_name").strip()
        if not last_name:
            err_msg = "Last Name is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if not isinstance(last_name, str):
            err_msg = "Invalid Last Name provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        incident_type = params.get("incident_type")
        if not incident_type:
            err_msg = (
                "Incident Type is a required configuration parameter."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if incident_type not in INCIDENT_TYPES:
            err_msg = "Invalid value for Incident Type provided. Available values are 'User Service Restoration', 'User Service Request', 'Infrastructure Restoration', 'Infrastructure Event', and 'Security Incident'."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        urgency = params.get('urgency')
        if not urgency:
            err_msg = "Urgency is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if urgency not in URGENCY:
            err_msg = "Invalid value for Urgency provided. Available values are 'Low', 'Medium', 'High' and 'Critical'."

            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        impacts = params.get('impact')
        if not impacts:
            err_msg = "Impact is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if impacts not in IMPACT:
            err_msg = "Invalid value for Impact provided. Available values are '1-Extensive/Widespread', '2-Significant/Large', '3-Moderate/Limited' and '4-Minor/Localized'."

            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_headers(self, configuration):
        """
        Get the headers for the given configuration.

        Parameters:
            configuration (type): Description of the parameter.

        Returns:
            type: Description of the return value.
        """
        token = self.generate_token(configuration, False)
        return self.bmc_helix_helper._add_user_agent({"Authorization": f"AR-JWT {token}", "Content-Type": "application/json"})

    def generate_token(self, configuration, is_from_validation):
        """
        Generates a token for authentication.

        Parameters:
            is_from_validation (bool): A flag indicating whether the request is from a validation process.

        Returns:
            str: The generated token.
        """

        headers = self.bmc_helix_helper._add_user_agent(
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            }
        )

        auth_params = configuration.get("auth", {})
        authBody = {
            "username": auth_params.get("username", "").strip(),
            "password": auth_params.get("password", ""),
        }
        try:
            response = self.bmc_helix_helper.api_helper(
                logger_msg="generating a token",
                method="POST",
                url=f"http://{auth_params.get('servername')}:{auth_params.get('port')}/{LOGIN_URL}",
                headers=headers,
                data=authBody,
                is_validation=is_from_validation,
            )
            if response and response.text:
                return response.text
            else:
                raise BMCHelixPluginException(
                    "No response received. Token generation failed.")

        except BMCHelixPluginException as err:
            raise err
        except Exception as e:
            raise e

    def validate_auth_params(self, configuration, validation_err_msg):
        """Validate the Plugin authentication parameters.

        Args:
            configuration (dict): Plugin configuration parameters.
            validation_err_msg (str): Validation error message.
        Returns:
            cto.plugin_base.ValidateResult:
            ValidateResult object with success flag and message.
        """
        try:
            self.generate_token(configuration, is_from_validation=True)
            return ValidationResult(
                success=True,
                message="Validation successful.",
            )

        except BMCHelixPluginException as exp:
            self.logger.error(
                message=(f"{validation_err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=str(exp),
            )
        except Exception as exp:
            self.logger.error(
                message=(f"{validation_err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message="Unexpected error occurred. Check logs for more details.",
            )

    def get_available_fields(self, configuration):
        """Get list of all the available fields."""

        fields = [
            MappingField(
                label="Summary", value="Summary",
            ),
            MappingField(
                label="Description", value="Description",
            )
        ]
        return fields

    def get_default_mappings(
        self, configuration: dict
    ) -> Dict[str, List[FieldMapping]]:
        """Get default mappings."""
        return {
            "mappings": [
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="Summary",
                    custom_message="Netskope $appCategory alert: $alertName",
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="Description",
                    custom_message=(
                        "Alert ID: $id\nApp: $app\nAlert Name: $alertName\n"
                        "Alert Type: $alertType\nApp Category: $appCategory\n"
                        "User: $user"
                    ),
                ),
            ],
            "dedup": [],
        }

    def create_task(self, alert: Alert, mappings: Dict, queue: Queue) -> Task:
        """Create an issue/ticket on Jira platform."""
        try:
            auth_params = self.configuration.get("auth")
            url = f"http://{auth_params.get('servername')}:{auth_params.get('port')}/{TASK_URL}"
            params = {
                "fields": "(Incident Number, Status)"
            }

            payload = {
                "Status": "New",
                "Service_Type": INCIDENT_SERVICE_TYPE_MAPPING.get(self.configuration.get("service_type")),
                "Impact": IMPACT_MAPPING.get(self.configuration.get("impact")),
                "Urgency": URGENCY_MAPPING.get(self.configuration.get("urgency")),
                "First Name": self.configuration.get("first_name"),
                "Last Name": self.configuration.get("last_name"),
            }

            if mappings.get("Summary"):
                payload["Summary"] = mappings.get("Summary")
            if mappings.get("Description"):
                payload["Description"] = mappings.get("Description")

            response = self.bmc_helix_helper.api_helper(
                logger_msg="creating a Task",
                url=url,
                method="POST",
                params=params,
                headers=self.get_headers(self.configuration),
                data=json.dumps({"values": payload}),
            )
            result = response.get("values", {})
            incident_status = result.get("Status", "")
            link = response.get("_links", {}).get("self", [])
            if link and len(link):
                link = link[0].get("href", "")
            else:
                link = ""

            return Task(
                id=result.get("Incident Number", ""),
                status=STATE_MAPPINGS.get(incident_status, TaskStatus.OTHER),
                link=link,
            )

        except (BMCHelixPluginException, Exception) as err:
            self.logger.error(
                message=f"Failed to create a Task. Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise err

    def update_task(self, task: Task, alert: Alert, mappings, queue):
        """Return the task as it is."""
        return task

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        total_count = 0
        skip_count = 0
        auth_params = self.configuration.get("auth")
        url = f"http://{auth_params.get('servername')}:{auth_params.get('port')}/{GET_TASK_URL}"

        for task in tasks:
            try:
                params = {"q": f"Incident Number={task.id}"}
                response = self.bmc_helix_helper.api_helper(
                    logger_msg="get incident",
                    url=f"{url}",
                    method="GET",
                    headers=self.get_headers(self.configuration),
                    params=params
                )
                response = self.bmc_helix_helper.parse_response(
                    response, is_validation=False)
                if response:
                    result_data = {}
                    entries = response.get("entries", [])
                    if entries and len(entries) > 0:
                        result_data = entries[0]

                    if (result_data):
                        values = result_data.get("values", {})

                    task.status = STATE_MAPPINGS.get(
                        values.get("Status"), TaskStatus.OTHER)
                else:
                    task.status = TaskStatus.DELETED
                total_count += 1
            except (BMCHelixPluginException, Exception) as err:
                self.logger.error(
                    message=f"{self.log_prefix}: Error occurred while getting a Task. Error: {err}",
                    details=str(traceback.format_exc()),
                )
                skip_count += 1
                continue

        self.logger.info(
            f"{self.log_prefix}: Successfully synced {total_count} ticket(s) from {PLATFORM_NAME}."
        )
        if skip_count:
            self.logger.info(
                f"{self.log_prefix}: Failed to sync {skip_count} ticket(s) from {PLATFORM_NAME}."
            )

        return tasks

    def get_queues(self) -> List[Queue]:
        """
        Return a list of Queue objects.
        """
        return [Queue(label="No Group", value="no_group")]
