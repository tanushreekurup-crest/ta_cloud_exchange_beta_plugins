"""_summary_"""
from datetime import datetime
import json
import requests
import time

from netskope.integrations.grc.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.common.utils import add_user_agent
from netskope.integrations.grc.models.configuration import (
    TargetMappingFields,
    MappingType,
)

MAX_RETRY_COUNT = 4
MAX_APPS_TO_PUSH = 10000
BASE_URL = "https://api.securityscorecard.io"
SIGNAL_ID = "netskope_ce-are.cci"


class SecurityScoreCard(PluginBase):
    """PLugin implementation for SecurityScoreCard"""

    def api_call_helper(self, url, method, data=None):
        config = self.configuration
        request_func = getattr(requests, method)
        headers = {"Authorization": f"Token {config.get('api_token')}"}
        headers = add_user_agent(headers)
        verify = self.ssl_validation
        proxies = self.proxy
        response = {}
        for attempt in range(MAX_RETRY_COUNT):
            resp = request_func(
                url=url, headers=headers, verify=verify, proxies=proxies, json=data
            )
            response_json = self.handle_response(resp)
            if resp.status_code == 200 or resp.status_code == 201:
                response = response_json
                break
            elif resp.status_code in [429, 503, 301] and attempt < (
                MAX_RETRY_COUNT - 1
            ):
                self.logger.info(
                    f"Too many requests occurred for {url}, retrying to make the API call. Retry count: {attempt + 1}."
                )
                retry_val = resp.headers.get("retry-after", 60)
                if retry_val > 300:
                    time.sleep(60)
                else:
                    time.sleep(retry_val)
        else:
            raise requests.exceptions.HTTPError("Maximum retry limit reached")
        return response

    def _validate_portfolio_names(self, portfolios, config):
        portfolio_names = config.get("portfolio_name")
        for portfolio in portfolios:
            if portfolio["name"] == portfolio_names:
                return True
        return False

    def get_portfolio_id(self):
        try:
            portfolios_dict = {}
            config = self.configuration
            url = f"{BASE_URL}/portfolios"
            results = self.api_call_helper(url, method="get")
            portfolios = results.get("entries", [])
            for portfolio in portfolios:
                portfolio_name = portfolio["name"]
                portfolio_id = portfolio["id"]
                portfolios_dict[portfolio_name] = portfolio_id

            portfolio_name = config.get("portfolio_name")
            portfolio_id = portfolios_dict.get(portfolio_name, None)
            if not portfolio_id:
                self.logger.error(
                    f"Provided Portfolio name '{portfolio_name}' is not available in SecurityScorecard."
                )
                raise requests.HTTPError(
                    f"Provided Portfolio name '{portfolio_name}' is not available in SecurityScorecard."
                )
            return portfolio_id

        except requests.exceptions.ProxyError:
            raise requests.HTTPError("Invalid proxy configuration.")
        except requests.exceptions.ConnectionError:
            raise requests.HTTPError(
                "Unable to establish connection, server is not reachable."
            )
        except requests.exceptions.HTTPError as ex:
            raise requests.HTTPError(f"Error occurred while pulling data. {ex}")
        except Exception as ex:
            raise requests.HTTPError(f"Error occurred while pulling data. Error: {ex}")

    def pull_vendors(self):
        try:
            portfolio_id = self.get_portfolio_id()
            url = f"{BASE_URL}/portfolios/{portfolio_id}/companies"
            results = self.api_call_helper(url, method="get")
            vendors = results.get("entries", [])
            return vendors

        except requests.exceptions.ProxyError:
            raise requests.HTTPError("Invalid proxy configuration.")
        except requests.exceptions.ConnectionError:
            raise requests.HTTPError(
                "Unable to establish connection, server is not reachable."
            )
        except requests.exceptions.HTTPError as ex:
            raise requests.HTTPError(f"Error occurred while pulling data. {ex}")
        except Exception as ex:
            raise requests.HTTPError(f"Error occurred while pulling data. Error: {ex}")

    def add_query_list(self, final_list, mapping_dict):
        query_dict = {}
        query_dict["operator"] = "=="
        operand_dict = mapping_dict["=="]
        query_dict["lhs"] = operand_dict[0].get("var")
        query_dict["rhs"] = operand_dict[1]
        final_list.append(query_dict)

    def get_query_builder_list(self, configuration_mapping_query):
        configuration_mapping_query = configuration_mapping_query.dict()
        query_builder_dict = {}
        final_list = []
        mapping_query = configuration_mapping_query["jsonQuery"]
        list_query = mapping_query.get("and")
        query_builder_dict["operation"] = "and"
        if not list_query:
            list_query = mapping_query.get("or")
            query_builder_dict["operation"] = "or"
        for mapping_dict in list_query:
            self.add_query_list(final_list, mapping_dict)
        query_builder_dict["query_builder_list"] = final_list
        return query_builder_dict

    def check_result(self, record_value, application_value):
        """To check value of the source fields is matching with the value of application field or not."""
        record_value = record_value.lower() if isinstance(record_value, str) else record_value
        if isinstance(application_value, list):
            for app_val in application_value:
                app_val = app_val.lower() if isinstance(app_val, str) else app_val
                if app_val == record_value:
                    return True
            else:
                return False

        application_value = application_value.lower() if isinstance(application_value, str) else application_value
        return record_value == application_value

    def list_of_application(self, final_dict, domain, app):
        if domain in final_dict:
            final_dict[domain].append(app)
        else:
            final_dict[domain] = [app]
        return final_dict

    def push(self, applications, mapping):
        """push method to store the data collected from the Netskope tenant into SecurityScorecard VRM.
        Args:
            applications (_type_): _description_
        """
        self.logger.info("Plugin SecurityScorecard: Executing push method.")
        query_builder_dict = self.get_query_builder_list(mapping)
        signal_list = []
        vendor_results = self.pull_vendors()
        self.logger.info(
            f"Plugin SecurityScorecard: Pulled {len(vendor_results)} number of companies from the provided portfolio."
        )
        if not vendor_results:
            self.logger.info(
                "No companies found on SecurityScorecard for the configured portfolio. Hence skipping the sharing."
            )
            return PushResult(
                success=True, message="Successfully pushed data to SecurityScorecard."
            )
        final_dict = {}
        operation = query_builder_dict.get("operation")
        skip_count = 0
        for app in applications:
            check_match = False
            app_dict = app.dict()
            for vendor in vendor_results:
                count = 0
                domain = vendor.get("domain", "")
                if not domain:
                    self.logger.info(
                        f"Domain not available for vendor {vendor.get('name')}. Hence, not considering this vendor for application {app_dict.get('applicationName')}."
                    )
                    continue
                for inner_list in query_builder_dict["query_builder_list"]:
                    count = count + 1
                    ssc_record = vendor.get(f"{inner_list['lhs']}")
                    applications_value = app_dict.get(inner_list["rhs"])
                    res = self.check_result(ssc_record, applications_value)
                    if res:
                        if operation == "or" or count == len(
                            query_builder_dict["query_builder_list"]
                        ):
                            final_dict = self.list_of_application(
                                final_dict, domain, app_dict
                            )
                            check_match = True
                            break
                    elif operation == "and":
                        break
            if not check_match:
                skip_count += 1
                self.logger.warn(
                    f"Application '{app_dict.get('applicationName')}' match is not available in SecurityScorecard, skipping sharing of this application."
                )

        self.logger.info(
            "Plugin SecurityScorecard: Sending the applications to Security Scorecard."
        )
        shared_count = 0
        for domain, app_details in final_dict.items():
            for app_detail in app_details:
                notes = f"Application Name: {app_detail.get('applicationName')}, Cloud Confidence Index: {app_detail.get('cci')}, CCL: {app_detail.get('ccl')}, Category Name: {app_detail.get('categoryName')}, Deep Link: {app_detail.get('deepLink')}"
                signal_dict = {
                    "op": "add",
                    "value": {"summary": notes, "domain": domain},
                }
                signal_list.append(signal_dict)
                if len(signal_list) == MAX_APPS_TO_PUSH:
                    try:
                        _ = self.api_call_helper(
                            f"{BASE_URL}/signals/by-type/{SIGNAL_ID}",
                            method="patch",
                            data=signal_list,
                        )
                        shared_count += len(signal_list)
                        signal_list = []

                    except requests.exceptions.ProxyError:
                        raise requests.HTTPError("Invalid proxy configuration.")
                    except requests.exceptions.ConnectionError:
                        raise requests.HTTPError(
                            "Unable to establish connection, server is not reachable."
                        )
                    except requests.exceptions.HTTPError as ex:
                        raise requests.HTTPError(
                            f"Error occurred while pushing data. {ex}"
                        )
                    except Exception as ex:
                        raise requests.HTTPError(
                            f"Error occurred while pushing data. Error: {ex}"
                        )
        try:
            if signal_list:
                result = self.api_call_helper(
                    f"{BASE_URL}/signals/by-type/{SIGNAL_ID}",
                    method="patch",
                    data=signal_list,
                )
                shared_count += len(signal_list)
        except requests.exceptions.ProxyError:
            raise requests.HTTPError("Invalid proxy configuration.")
        except requests.exceptions.ConnectionError:
            raise requests.HTTPError(
                "Unable to establish connection, server is not reachable."
            )
        except requests.exceptions.HTTPError as ex:
            raise requests.HTTPError(f"Error occurred while pushing data. {ex}")
        except Exception as ex:
            raise requests.HTTPError(f"Error occurred while pushing data. Error: {ex}")
        self.logger.info(
            f"Total {shared_count} applications shared successfully with SecurityScorecard and "
            f"{skip_count} applications were skipped."
        )
        return PushResult(
            success=True, message="Successfully pushed data to SecurityScorecard."
        )

    def validate(self, data):
        """Validate the Plugin configuration parameters.

        Validation for all the parameters mentioned in the manifest.json for the existence and
        data type. Method returns the grc.plugin_base.ValidationResult object with success = True in the case
        of successful validation and success = False and a error message in the case of failure.
        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        self.logger.info(
            "SecurityScoreCard Plugin: Executing validate method for SecurityScoreCard plugin."
        )
        if (
            "portfolio_name" not in data
            or not data["portfolio_name"]
            or type(data["portfolio_name"]) != str
        ):
            self.logger.error(
                "SecurityScoreCard Plugin: Validation error occurred Error: Invalid SecurityScoreCard portfolio name provided."
            )
            return ValidationResult(
                success=False,
                message="Invalid SecurityScoreCard portfolio name provided.",
            )

        if (
            "api_token" not in data
            or not data["api_token"]
            or type(data["api_token"]) != str
        ):
            self.logger.error(
                "SecurityScoreCard Plugin: Validation error occurred Error: Invalid api_token provided."
            )
            return ValidationResult(
                success=False,
                message="Invalid api_token provided.",
            )

        try:
            headers = {"Authorization": f"Token {data['api_token']}"}
            url = f"{BASE_URL}/portfolios"
            response = requests.get(
                url=url,
                verify=self.ssl_validation,
                proxies=self.proxy,
                headers=add_user_agent(headers),
            )
            if (response.status_code in [401, 403]):
                self.logger.error("Plugin SecurityScorecard: Validation error occurred. Field - API Token.")
                return ValidationResult(
                    success=False, message="Invalid API Token provided.",
                )
            elif (response.status_code != 200):
                self.logger.error(
                    f"SecurityScoreCard Plugin: HTTP request returned with status code {response.status_code}."
                )
                return ValidationResult(
                    success=False,
                    message="Error occurred while validating",
                )
            result = response.json()
            portfolios = result.get("entries", [])
            if self._validate_portfolio_names(portfolios, data) == False:
                self.logger.error(
                    "Plugin SecurityScorecard: Validation error occurred. Field - Portfolio Name."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Portfolio Name provided."
                )
        except Exception as e:
            self.logger.error(
                "SecurityScoreCard Plugin: Error while fetching data from SecurityScoreCard."
                + repr(e)
            )
            return ValidationResult(
                success=False,
                message="Validation failed. Check the input configuration.",
            )

        return ValidationResult(
            success=True,
            message="Validation successfull for SecurityScoreCard plugin",
        )

    def handle_response(self, resp):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned
                from API call.
        Returns:
            dict: Returns the dictionary of response JSON when the
                response code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        if resp.status_code == 200 or resp.status_code == 201:
            try:
                return resp.json()
            except ValueError:
                raise requests.exceptions.HTTPError(
                    "Exception occurred while parsing JSON response."
                )
        elif resp.status_code in [429, 503, 301]:
            return {}
        elif resp.status_code == 401:
            raise requests.exceptions.HTTPError(
                "Received exit code 401, Authentication Error."
            )
        elif resp.status_code == 403:
            raise requests.exceptions.HTTPError(
                "Received exit code 403, Forbidden User."
            )
        elif resp.status_code >= 400 and resp.status_code < 500:
            raise requests.exceptions.HTTPError(
                f"Received exit code {resp.status_code}, HTTP client Error."
            )
        elif resp.status_code >= 500 and resp.status_code < 600:
            raise requests.exceptions.HTTPError(
                f"Received exit code {resp.status_code}, HTTP server Error."
            )
        else:
            raise requests.exceptions.HTTPError(
                f"Received exit code {resp.status_code}, HTTP Error."
            )

    def get_target_fields(self, plugin_id, plugin_parameters):
        """Get available Target fields."""
        return [
            TargetMappingFields(
                label="Company Name",
                type=MappingType.STRING,
                value="name",
            ),
            TargetMappingFields(
                label="Domain",
                type=MappingType.STRING,
                value="domain",
            ),
        ]
