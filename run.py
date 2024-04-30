import os
from datetime import datetime
from time import sleep
import logging
import asyncio
from typing import AsyncIterator, Tuple
from asyncstdlib import enumerate
from pip._vendor.typing_extensions import Iterator
from solders.pubkey import Pubkey
from solders.rpc.config import RpcTransactionLogsFilterMentions
from solana.rpc.websocket_api import connect
from solana.rpc.commitment import Finalized
from solana.rpc.api import Client
from solana.exceptions import SolanaRpcException
from websockets.exceptions import ConnectionClosedError, ProtocolError
from typing import List

# Type hinting imports
from solana.rpc.commitment import Commitment
from solana.rpc.websocket_api import SolanaWsClientProtocol
from solders.rpc.responses import RpcLogsResponse, SubscriptionResult, LogsNotification, GetTransactionResp
from solders.signature import Signature
from solders.transaction_status import UiPartiallyDecodedInstruction, ParsedInstruction
import requests
import math


# Raydium Liquidity Pool V4
RaydiumLPV4 = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8"
URI = "https://api.mainnet-beta.solana.com"  # "https://api.devnet.solana.com" | "https://api.mainnet-beta.solana.com"
WSS = "wss://api.mainnet-beta.solana.com"  # "wss://api.devnet.solana.com" | "wss://api.mainnet-beta.solana.com"
solana_client = Client(URI)
METADATA_PROGRAM_ID = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"
LAMPORTS_PER_SOL = 1000000000

log_instruction = "init_pc_amount"
# log_instruction = "initialize2"

# Init logging
logging.basicConfig(filename='app.log', filemode='a', level=logging.DEBUG)

async def main():
    """The client as an infinite asynchronous iterator:"""
    async for websocket in connect(WSS):
        try:
            subscription_id = await subscribe_to_logs(
                websocket,
                RpcTransactionLogsFilterMentions(RaydiumLPV4),
                Finalized
            )
            # Change level debugging to INFO
            logging.getLogger().setLevel(logging.INFO)  # Logging
            async for i, signature in enumerate(process_messages(websocket, log_instruction)):  # type: ignore
                logging.info(f"{i=}")  # Logging
                try:
                    await get_tokens(signature,
                               RaydiumLPV4)  # AttributeError: 'NoneType' object has no attribute 'transaction'
                except (AttributeError, SolanaRpcException) as err:
                    # Omitting httpx.HTTPStatusError: Client error '429 Too Many Requests'
                    # Sleep 5 sec, and try connect again
                    # Start logging
                    logging.exception(err)
                    logging.info("sleep for 5 seconds and try again")
                    # End logging
                    sleep(5)
                    continue
        except (ProtocolError, ConnectionClosedError) as err:
            # Restart socket connection if ProtocolError: invalid status code
            logging.exception(err)  # Logging
            print(f"Danger! Danger!", err)
            continue
        except KeyboardInterrupt:
            if websocket:
                await websocket.logs_unsubscribe(subscription_id)

#pairfinder
async def subscribe_to_logs(websocket: SolanaWsClientProtocol,
                            mentions: RpcTransactionLogsFilterMentions,
                            commitment: Commitment) -> int:
    await websocket.logs_subscribe(
        filter_=mentions,
        commitment=commitment
    )
    first_resp = await websocket.recv()
    return get_subscription_id(first_resp)  # type: ignore

#pairfinder
def get_subscription_id(response: SubscriptionResult) -> int:
    return response[0].result

#pairfinder
async def process_messages(websocket: SolanaWsClientProtocol,
                           instruction: str) -> AsyncIterator[Signature]:
    """Async generator, main websocket's loop"""
    async for idx, msg in enumerate(websocket):
        value = get_msg_value(msg)
        if not idx % 100:
            print(f"{idx=}")
        for log in value.logs:
            if instruction not in log:
                continue
            # Start logging
            logging.info(value.signature)
            logging.info(log)
            # Logging to messages.json
            with open("messages.json", 'a', encoding='utf-8') as raw_messages:
                raw_messages.write(f"signature: {value.signature} \n")
                raw_messages.write(msg[0].to_json())
                raw_messages.write("\n ########## \n")
            # End logging
            yield value.signature


#pairfinder
def get_msg_value(msg: List[LogsNotification]) -> RpcLogsResponse:
    return msg[0].result.value

async def get_lpLockedPct(token_address):
    url = f"https://api.rugcheck.xyz/v1/tokens/{token_address}/report"
    print(url)
    with requests.get(url) as data:
        rugcheckdata = data.json()
        try:
            lpLockedPct = rugcheckdata['markets'][0]['lp']['lpLockedPct']
            print(f"tokenAddress: {token_address}")
            print(f"reserveSupply: {rugcheckdata['markets'][0]['lp']['reserveSupply']}")
            print(f"currentSupply: {rugcheckdata['markets'][0]['lp']['currentSupply']}")
            print(f"lpLocked: {rugcheckdata['markets'][0]['lp']['lpLocked']}")
        except Exception as e:
            lpLockedPct = "failed"

    return lpLockedPct

async def calc_lpLockedPct(
        instruction: UiPartiallyDecodedInstruction,
        signature: Signature):

    # EXTRACT LPRESERVE
    accounts = instruction.accounts
    #lpmint = accounts[7]
    lpReserve = -69 #lpReserve arbitrarily set to -69
    transaction_0 = solana_client.get_transaction(
        signature,
        encoding="jsonParsed",
        max_supported_transaction_version=0
    )
    meta_data = get_meta(transaction_0)
    innerInstructions_0 = meta_data.inner_instructions  # initializeMint

    for x in innerInstructions_0:
        for y in x.instructions:
            try:
                if Pubkey.from_string(y.parsed['info']['mint']) == accounts[7] and y.parsed['type'] == 'initializeMint':
                    lpDecimals = y.parsed['info']['decimals']
                elif Pubkey.from_string(y.parsed['info']['mint']) == accounts[7] and y.parsed['type'] == 'mintTo':
                    lpReserve = y.parsed['info']['amount']
                    lpReserve_ = y.parsed['info']['amount']
                    #print(f"lpReserve: {lpReserve}")
                    #lpReserve: parseInt(lpMintInstruction.parsed.info.amount),
                else:
                    pass
            except:
                pass

            try:
                if Pubkey.from_string(y.parsed['type']) == accounts[7] and y.parsed['type'] == 'initializeMint':
                    lpDecimals = y.parsed['info']['decimals']

                else:
                    pass
            except:
                pass

    # LP BURN CALCULATION
    accInfo = solana_client.get_account_info_json_parsed(accounts[7])
    lpLockedPct = ""
    try:
        accdata_ = accInfo.value.data
        actual_supply = accdata_.parsed['info']['supply']

        if lpReserve_ == -69:  # This means that we were unable to pull lpReserve and cannot calculate burn amount
            burnAmt = "Failed"
            burnPct = "Failed"
        else:
            #lpReserve = float(lpReserve) / math.pow(10, int(accdata_.parsed['info']['decimals']))
            # actual_supply = float(accdata_.parsed['info']['supply']) / math.pow(10, int(accdata_.parsed['info']['decimals']))
            print(f"reserveSupply (myCalc): {lpReserve}")
            print(f"currentSupply (myCalc): {actual_supply}")
            # Calculate burn percentage
            lpReserve = float(lpReserve)
            actual_supply = float(actual_supply)
            burnAmt = lpReserve - actual_supply #Token for Token burn amount
            print(f"lplocked (myCalc): {burnAmt}")
            burnPct = (burnAmt / lpReserve) * 100 #Percentage burn calculaion

        lpLockedPct_ = str("{:.20f}".format(burnPct))
    except Exception as e:
        print(f"Exception (calc_lpLockedPct): {e}")
        pass

    return lpLockedPct_


#Pairfinder
def get_instructions(
        transaction: GetTransactionResp
) -> List[UiPartiallyDecodedInstruction | ParsedInstruction]:
    instructions = transaction \
        .value \
        .transaction \
        .transaction \
        .message \
        .instructions
    return instructions

#NOT PairFinder - custom script
def get_meta(
        transaction: GetTransactionResp
) -> List[UiPartiallyDecodedInstruction | ParsedInstruction]:
    meta = transaction \
        .value \
        .transaction \
        .meta
    return meta

def get_basemint(
        instruction: UiPartiallyDecodedInstruction):
    accounts = instruction.accounts
    basemint = ""
    quoteMint = ""

    if accounts[8] != "So11111111111111111111111111111111111111112":
        baseMint = accounts[8]
        quoteMint = accounts[9]
    else:
        quoteMint = accounts[8]
        baseMint = accounts[9]

    # Added this because I was occasionally getting it wrong despite it all
    if basemint == "So11111111111111111111111111111111111111112":
        basemint = quoteMint

    return baseMint

#Pairfinder - customized
async def get_tokens(signature: Signature, RaydiumLPV4: Pubkey) -> None:
    """httpx.HTTPStatusError: Client error '429 Too Many Requests'
    for url 'https://api.mainnet-beta.solana.com'
    For more information check: https://httpstatuses.com/429
    """
    transaction = solana_client.get_transaction(
        signature,
        encoding="jsonParsed",
        max_supported_transaction_version=0
    )
    # Start logging to transactions.json
    #TODO: Study these data outputs
    #print(f"Print transaction RAW:\n{transaction}")
    #print(f"Print signature RAW:\n{signature}")
    #print(f"Print transaction.to_json():\n{transaction.to_json()}")

    with open("transactions.json", 'a', encoding='utf-8') as raw_transactions:
        raw_transactions.write(f"signature: {signature}\n")
        raw_transactions.write(transaction.to_json())
        raw_transactions.write("\n ########## \n")
    # End logging
    instructions = get_instructions(transaction)
    #print(f"Print instructions RAW:\n{instructions}")
    filtered_instuctions = instructions_with_program_id(instructions, RaydiumLPV4)
    logging.info(filtered_instuctions)

    for instruction in filtered_instuctions:
        tokens = get_tokens_info(instruction)
        print_table(tokens)
        print(f"True, https://solscan.io/tx/{signature}")

        # =================================
        # HERE HERE HERE HERE HERE HERE HERE
        # THIS IS WHERE WE CALL FUNCTION TO
        # GATHER POOL KEY DATA
        # =================================

        mint = get_basemint(instruction)
        myCalc_lpLockedPct = await calc_lpLockedPct(instruction, signature)
        rugCheck_lpLockedPct = await get_lpLockedPct(mint)
        print(" = = = = = = = = rugcheck.xyz  versus myCalc = = = = = = = = ")
        print(f"My Calculated lpLockedPct: {myCalc_lpLockedPct}")
        print(f"RugChecker lpLockedPct: {rugCheck_lpLockedPct}")


#Pairfinder
def instructions_with_program_id(
        instructions: List[UiPartiallyDecodedInstruction | ParsedInstruction],
        program_id: str
) -> Iterator[UiPartiallyDecodedInstruction | ParsedInstruction]:
    return (instruction for instruction in instructions
            if instruction.program_id == program_id)

#PairFinder
def get_tokens_info(
        instruction: UiPartiallyDecodedInstruction | ParsedInstruction
) -> Tuple[Pubkey, Pubkey, Pubkey]:
    accounts = instruction.accounts
    Pair = accounts[4]
    Token0 = accounts[8]
    Token1 = accounts[9]
    # Start logging
    logging.info("find LP !!!")
    logging.info(f"\n Token0: {Token0}, \n Token1: {Token1}, \n Pair: {Pair}")
    # End logging
    return (Token0, Token1, Pair)

#PairFinder
def print_table(tokens: Tuple[Pubkey, Pubkey, Pubkey]) -> None:
    data = [
        {'Token_Index': 'Token0', 'Account Public Key': tokens[0]},  # Token0
        {'Token_Index': 'Token1', 'Account Public Key': tokens[1]},  # Token1
        {'Token_Index': 'LP Pair', 'Account Public Key': tokens[2]}  # LP Pair
    ]
    print("============NEW POOL DETECTED====================")
    header = ["Token_Index", "Account Public Key"]
    print("│".join(f" {col.ljust(15)} " for col in header))
    print("|".rjust(18))
    for row in data:
        print("│".join(f" {str(row[col]).ljust(15)} " for col in header))


#Pairfinder
if __name__ == "__main__":
    RaydiumLPV4 = Pubkey.from_string(RaydiumLPV4)
    asyncio.run(main())
