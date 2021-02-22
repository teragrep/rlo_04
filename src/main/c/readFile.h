/*
 * rsyslog regex perfect file input plugin 
 * Copyright (C) 2021  Suomen Kanuuna Oy
 *  
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *  
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *  
 *  
 * Additional permission under GNU Affero General Public License version 3
 * section 7
 *  
 * If you modify this Program, or any covered work, by linking or combining it 
 * with other code, such other code is not for that reason alone subject to any
 * of the requirements of the GNU Affero GPL version 3 as long as this Program
 * is the same Program as licensed from Suomen Kanuuna Oy without any additional
 * modifications.
 *  
 * Supplemented terms under GNU Affero General Public License version 3
 * section 7
 *  
 * Origin of the software must be attributed to Suomen Kanuuna Oy. Any modified
 * versions must be marked as "Modified version of" The Program.
 *  
 * Names of the licensors and authors may not be used for publicity purposes.
 *  
 * No rights are granted for use of trade names, trademarks, or service marks
 * which are in The Program if any.
 *  
 * Licensee must indemnify licensors and authors for any liability that these
 * contractual assumptions impose on licensors and authors.
 *  
 * To the extent this program is licensed as part of the Commercial versions of
 * Teragrep, the applicable Commercial License may apply to this file if you as
 * a licensee so wish it.
 */

/*
 * read a multi-line message from a stream file.
 * The message is captured from startRegex to next startRegex
 * unless timeout occurs. Regex must be precompiled.
 * TODO does not handle discardTruncatedMsg or msgDiscardingError, everything is
 * sent
 *
 */

#include <regex.h>
#include "runtime/typedefs.h"
#include "runtime/rsyslog.h" // for rsObjID
#include "stream.h"
#include "runtime/errmsg.h"
#include "runtime/datetime.h"

/*
 * match types
 * normal match: hit-scan from start (@) between start of first match ([xx]) to start of second match ([yy])
 * @[xx]---[yy]
 *
 * normal large match: hit-scan from start (@) between start of first match ([xx]) to start of second match ([yy]) exceeding max line length
 * @[xx]-...-[yyy] where "[xx]-...-" > glblGetMaxLine() - headersReserve
 *
 * prematch: hit-scan between start (@) and first match ([xx]) has content with no matching header (+++)
 * @+++[xx]---[yy]
 *
 * prematch large match: hit-scan between start (@) and first match ([xx]) has content with no matching header (+++) exceeding max line length
 * @+...+[xx]---[yy] where CONCAT("[xx]"), " (prematch@48577) ", "+...+") > glblGetMaxLine() - headersReserve
 */

static rsRetVal
restoreState(cstr_t *prevMsgSegment, regex_t *preg, regmatch_t *start_match, int64 *bolOffset, int *nFound, int localDebug, int bEscapeLF) {
	DEFiRet;
	// there is content, but does it match, who is to find out if not us

	// state-files have non-finalized stuff
	cstrFinalize(prevMsgSegment);

	// scan pThis->prevMsgSegment for BOL
	uchar *prevMesg = rsCStrGetSzStrNoNULL(prevMsgSegment);
	int prevMesgLen = cstrLen(prevMsgSegment);
	int iter = 0;
	int nlCount = 0;

	while (iter < prevMesgLen) {
		/*
		 * this will not work for \\0
		 * and because escaping schematics do not make difference between
		 * "\\n" from the stream and escaping done here so we really can not say anything sure about it
		 * suggestions are welcome how to fix this case, personally I would use escaping
		 * while sending only and store \n and \0 in the state-file or encode them as something
		 * else in the state-file if the underlying code does not handle \0
		 * -kortemik 2020-09-30
		 */

		if(bEscapeLF) {
			if (prevMesg[iter] == 'n') {
				if (iter != 0) {
					if (prevMesg[iter-1] == '\\') {
						//  only first line is ever checked
						if (nlCount == 0) {
							cstr_t *firstLine = NULL;
							CHKiRet(cstrConstruct(&firstLine));
							CHKiRet(rsCStrAppendStrWithLen(firstLine, rsCStrGetSzStrNoNULL(prevMsgSegment), iter-1));
							cstrFinalize(firstLine);
							nFound += !regexec(preg, (char*)rsCStrGetSzStrNoNULL(firstLine), 1, start_match, 0);
							if (localDebug)
								DBGPRINTF("[readMultiline] state-found at %s\n", (char*)rsCStrGetSzStrNoNULL(firstLine));
							cstrDestruct(&firstLine);
							// not translating offsets as it's first line only so they are absolute in any case
						}
						*bolOffset = iter+1;
						nlCount++;
					}
				}
			}
			iter++;
		}
		else {
			if (prevMesg[iter] == '\n') {
				//  only first line is ever checked
				if (nlCount == 0) {
					cstr_t *firstLine = NULL;
					CHKiRet(cstrConstruct(&firstLine));
					CHKiRet(rsCStrAppendStrWithLen(firstLine, rsCStrGetSzStrNoNULL(prevMsgSegment), iter));
					cstrFinalize(firstLine);
					nFound += !regexec(preg, (char*)rsCStrGetSzStrNoNULL(firstLine), 1, start_match, 0);
					cstrDestruct(&firstLine);
					// not translating offsets as it's first line only so they are absolute in any case
				}
				*bolOffset = iter+1;
				nlCount++;
			}
			iter++;
		}
		if(localDebug)
			DBGPRINTF("[readMultiline] initial storedBol %p\n", &(prevMesg[*bolOffset]));
	}

	// lineMatch is more strict, if it found we don't need to
	if (nFound == 0) {
		cstrFinalize(prevMsgSegment);
		// forbid EOL matching as EndOfString is not EOL
		nFound += !regexec(preg, (char*)rsCStrGetSzStrNoNULL(prevMsgSegment), 1, start_match, REG_NOTEOL);
	}

	// safety check
	if (start_match->rm_so != 0) {
		/*
		 * match was not at the beginning, this is not a valid case at all.
		 * perhaps someone changed the regex and did not clear the state-files
		 *
		 */
		LogError(0, RS_RET_ERR,
				"imfile error: state-file contains "
				"a message that does not start with a regex match; "
				"processing will halt as this is not a valid condition. "
				"Perhaps one changed the regex and did not clear the statefiles.");
		if(localDebug) {
			DBGPRINTF("[readMultiline] faulty state-file rm_so %d\n", start_match->rm_so);
			DBGPRINTF("[readMultiline] faulty state-file contained %s\n", (char*)rsCStrGetSzStrNoNULL(prevMsgSegment));
		}
		CHKiRet(RS_RET_ERR);
	}

finalize_it:
	RETiRet;
}

static rsRetVal
isAllowedSuffix(uchar *filename, cstr_t *prevMsgSegment, int localDebug) {
	DEFiRet;
	if (localDebug)
		DBGPRINTF("[readMultiline] filename %s\n", filename);

	long unsigned int suffixIter = 0;
	long unsigned int dotOffset = 0;
	while (suffixIter < ustrlen(filename)) {
		// find the last dot
		if (filename[suffixIter] == '.')
			dotOffset = suffixIter;
		suffixIter++;
	}
	if (dotOffset != 0) {
		if (localDebug)
			DBGPRINTF("[readMultiline] filename suffix %s\n", &filename[dotOffset]);

		// FIXME use strrchr for dot lookup
		if (dotOffset+3 == ustrlen(filename)) {
			// perhaps .gz
			if (!strcmp(&filename[dotOffset], ".gz")) {
				DBGPRINTF("[readMultiline] filename suffix not permitted skipping %s\n", &filename[dotOffset]);
				if(prevMsgSegment != NULL) {
					cstrDestruct(&prevMsgSegment);
				}
				// CHKiRet(strmSeek(pThis, 0)); // is not exposed
				ABORT_FINALIZE(RS_RET_EOF);
			}
		}
		else if (dotOffset+4 == ustrlen(filename)) {
			// perhaps .zip
			if (!strcmp(&filename[dotOffset], ".zip")) {
				DBGPRINTF("[readMultiline] filename suffix not permitted skipping %s\n", &filename[dotOffset]);
				if(prevMsgSegment != NULL) {
					cstrDestruct(&prevMsgSegment);
				}
				// CHKiRet(strmSeek(pThis, 0)); // is not exposed
				ABORT_FINALIZE(RS_RET_EOF);
			}
		}
	}

finalize_it:
	RETiRet;
}

rsRetVal
readMultiLine(strm_t *pThis, cstr_t **ppCStr, regex_t *preg, const sbool bEscapeLF,
		const sbool discardTruncatedMsg, const sbool msgDiscardingError, int64 *const strtOffs)
{
	DBGPRINTF("[readMultiline] entrypoint\n");
	DEFiRet;
	/*
	 * cases:
	 * 1) c is \n (or \0) -> test for ^xyz$ match with preceeding string
	 * TODO case 1 should be able to do case 2 when passed with EOF as EOL
	 * 2) c is after \n (or \0) (or at start) -> test for ^abc match proceeding string
	 * 3) c is somewhere else -> blacklist ^ and $ matching and test
	 */
	int enableCase2 = 1; // head ^ matching with multi-line
	// TODO make enableCase3 configureable
	int enableCase3 = 0; // true floating matching

	// TODO make headersReserve configureable
	int headersReserve = 0;
	if (glblGetMaxLine() >= 8192)
		headersReserve = (8192/10)*2;

	uchar c;
	int64 currOffs;
	int64 bolOffset = 0; // beginning of line offset
	regmatch_t *start_match = (regmatch_t *) calloc(1,sizeof(regmatch_t));
	int localDebug = 0;

	if (start_match == NULL) {
		CHKiRet(RS_RET_OUT_OF_MEMORY);
	}

	// match counter
	int nFound = 0;
	// store pointer which allow line matching within stream matching

	/*
	 * initialize previous message
	 * it will contain max one match at the zero offset on function exit
	 */
	if(pThis->prevMsgSegment == NULL) {
		CHKiRet(cstrConstruct(&pThis->prevMsgSegment));
		if(localDebug)
			DBGPRINTF("[readMultiline] state-file empty\n");
	}
	else {
		//restoreState(cstr_t *prevMsgSegment, regex_t *preg, regmatch_t *start_match, int *bolOffset, int *nFound, int localDebug, int bEscapeLF)
		CHKiRet(restoreState(pThis->prevMsgSegment, preg, start_match, &bolOffset, &nFound, localDebug, bEscapeLF));
	}
	if (localDebug) {
		DBGPRINTF("[readMultiline] after state-file nFound %d with bolOffset %llu\n", nFound, bolOffset);
	}

	// check offset
	CHKiRet(strm.GetCurrOffset(pThis, &currOffs));
	if (currOffs != pThis->strtOffs) {
		if (localDebug)
			DBGPRINTF("[readMultiline] currOffs(%llu) != pThis->strtOffs(%llu)\n", currOffs, pThis->strtOffs);
	}


	while ((iRet = strm.ReadChar(pThis, &c)) != RS_RET_EOF) {
		// something might go wrong with stream reads
		CHKiRet(iRet);
		if(localDebug)
			DBGPRINTF("[readMultiline] strmReadChar %c\n", c);

		int lineMatched = 0;
		int isBolChar = 0;
		// case 1: handle null and newline as the line breakers, this will do tail matching (xyz$) and (^xyz$)
		if (c == '\n' || c == '\0') {
			isBolChar = 1;
			// line matching

			// \n or \0 might be the first characters as well
			cstrFinalize(pThis->prevMsgSegment);
			if (bolOffset == 0) {
				uchar *prevMesg = rsCStrGetSzStrNoNULL(pThis->prevMsgSegment);
				// null, then beginning of the content
				if(localDebug)
					DBGPRINTF("[readMultiline] case 1: storedBol was NULL set to start of string %p\n", (char*)&(prevMesg[bolOffset]));
			}

			// FIXME $ match to EOF
			if (nFound > 0) {

				regoff_t firstEnd = start_match->rm_eo;
				uchar *prevMesg = rsCStrGetSzStrNoNULL(pThis->prevMsgSegment);
				/*
				 *  if we have a match from later matching, and current BOL is before start_match->rm_eo,
				 *  it's not valid: we do not allow overlapping matching
				 */
				if ( bolOffset > firstEnd ) {
					lineMatched += !regexec(preg, (char*)&(prevMesg[bolOffset]), 1, start_match, 0);
					if (lineMatched && localDebug)
						DBGPRINTF("[readMultiline] case 1: lineMatching second nFound %d\n", nFound+lineMatched);
				}

			}
			else {
				uchar *prevMesg = rsCStrGetSzStrNoNULL(pThis->prevMsgSegment);
				lineMatched += !regexec(preg, (char*)&(prevMesg[bolOffset]), 1, start_match, 0);
				if (lineMatched) {
					if(localDebug)
						DBGPRINTF("[readMultiline] case 1: lineMatching first nFound %d against %s\n", nFound+lineMatched, (char*)&(prevMesg[bolOffset]));
				}
				else {
					if(localDebug)
						DBGPRINTF("[readMultiline] case 1: lineMatching against %s\n", (char*)&(prevMesg[bolOffset]));
				}
			}

			// escape if needed and append
			if (c == '\n') {
				if(bEscapeLF) {
					CHKiRet(rsCStrAppendStrWithLen(pThis->prevMsgSegment, (uchar*)"\\n", 2));
					if (lineMatched)
						// belongs to match
						start_match->rm_eo += 2;
				} else {
					CHKiRet(cstrAppendChar(pThis->prevMsgSegment, '\n'));
					if (lineMatched)
						// belongs to match
						start_match->rm_eo += 1;
				}
			}
			else if (c == '\0') {
				// null byte is always escaped
				CHKiRet(rsCStrAppendStrWithLen(pThis->prevMsgSegment, (uchar*)"\\0", 2));
				if (lineMatched && nFound > 1)
					start_match->rm_eo += 2;
			}
			nFound += lineMatched;

			// offsets are local to the string, translate them to be global ones, if needed
			if (lineMatched) {
				uchar *prevMesg = rsCStrGetSzStrNoNULL(pThis->prevMsgSegment);
				if (bolOffset > 0) {
					int delta =  (int)bolOffset; // will break with >2G lines, but then again so does regex
					start_match->rm_so = (start_match->rm_so)+delta;
					start_match->rm_eo = (start_match->rm_eo)+delta;
					if(localDebug)
						DBGPRINTF("[readMultiline] case 1: delta %d stored rm_so %d rm_eo %d\n", delta, start_match->rm_so, start_match->rm_eo);
				}
			}

			// save next line location
			bolOffset = cstrLen(pThis->prevMsgSegment);

		}
		// cases: 2, 3
		/*
		 *  TODO: perf fix, one can merge cases 1 and 2 to line by line handling if EOF is fed to line reader
		 *  and by saving left over from match to statefile, instead of just last match
		 */
		else {
			// stream matching
			if (!isBolChar) {
				CHKiRet(cstrAppendChar(pThis->prevMsgSegment, c));
				cstrFinalize(pThis->prevMsgSegment);
			}
			int streamFound = 0;
			if (nFound > 0) {
				if (enableCase2) {
					// case 2: second match: try head matching ^abc
					regoff_t firstEnd = start_match->rm_eo;
					uchar *prevMesg = rsCStrGetSzStrNoNULL(pThis->prevMsgSegment);
					// check BOL location to be after rm_eo to ensure no overlapping matching
					if ( bolOffset > firstEnd ) {
						lineMatched += !regexec(preg, (char*)&(prevMesg[bolOffset]), 1, start_match, REG_NOTEOL);
						if (lineMatched && localDebug)
							DBGPRINTF("[readMultiline] case 2: second nFound %d\n", nFound+lineMatched);
					}
				}
				if (enableCase3) {
					// case 3: second match: head matching was not success try stream matching
					if (lineMatched == 0) {
						uchar *prevMesg = rsCStrGetSzStrNoNULL(pThis->prevMsgSegment);
						regoff_t firstEnd = start_match->rm_eo;
						streamFound += !regexec(preg, (char*)&(prevMesg[firstEnd+1]), 1, start_match, REG_NOTBOL|REG_NOTEOL);
						if (streamFound) {
							if (localDebug) {
								DBGPRINTF("[readMultiline] case 3: stream matched second search at offset %d\n", firstEnd+1);
								DBGPRINTF("[readMultiline] case 3: stream matching second nFound %d\n", nFound+streamFound);
							}
							int delta = &(prevMesg[firstEnd+1]) - prevMesg;
							if(localDebug)
								DBGPRINTF("[readMultiline] case 3: streamMatching delta %d\n", delta);
							start_match->rm_so = (start_match->rm_so)+delta;
							start_match->rm_eo = (start_match->rm_eo)+delta;
							if (localDebug) {
								DBGPRINTF("[readMultiline] case 3: streamMatching stored rm_so %d\n", start_match->rm_so);
								DBGPRINTF("[readMultiline] case 3: streamMatching stored rm_eo %d\n", start_match->rm_eo);
							}
						}
					}
				}
			}
			else {
				if (enableCase2) {
					// case 2: first match: do head matching ^abc
					uchar *prevMesg = rsCStrGetSzStrNoNULL(pThis->prevMsgSegment);


					lineMatched += !regexec(preg, (char*)&(prevMesg[bolOffset]), 1, start_match, REG_NOTEOL);
					if (lineMatched && localDebug)
						DBGPRINTF("[readMultiline] case 2: first match nFound %d\n", nFound+lineMatched);
				}
				if (enableCase3) {
					// case 3 first match: do stream matching
					if (lineMatched == 0) {
						streamFound += !regexec(preg, (char*)rsCStrGetSzStrNoNULL(pThis->prevMsgSegment), 1, start_match, REG_NOTBOL|REG_NOTEOL);
						if (streamFound && localDebug)
							DBGPRINTF("[readMultiline] case 3: stream matching first nFound %d\n", nFound+streamFound);
					}
				}
			}
			if (streamFound || lineMatched) {
				nFound += streamFound;
				nFound += lineMatched;
			}

			// offsets are local to the string, translate them to be global ones, if needed
			if (lineMatched) {
				uchar *prevMesg = rsCStrGetSzStrNoNULL(pThis->prevMsgSegment);
				if (bolOffset > 0) {
					int delta =  bolOffset;
					start_match->rm_so = (start_match->rm_so)+delta;
					start_match->rm_eo = (start_match->rm_eo)+delta;
					if(localDebug)
						DBGPRINTF("[readMultiline] case 2: delta %d stored rm_so %d rm_eo %d\n", delta, start_match->rm_so, start_match->rm_eo);
				}
			}
		}


		if (nFound == 1) {
			cstrFinalize(pThis->prevMsgSegment); // DEBUG
			if(localDebug) {
				uchar *prevMesg = rsCStrGetSzStrNoNULL(pThis->prevMsgSegment);
				DBGPRINTF("[readMultiline] nFound 1 line %s\n", (char*)rsCStrGetSzStrNoNULL(pThis->prevMsgSegment));
				DBGPRINTF("[readMultiline] nFound 1 storedBol %d with line %s\n", bolOffset, (char*)&(prevMesg[bolOffset]));
			}

			// check for garbage before the match
			if(start_match->rm_so != 0) {
				if(localDebug)
					DBGPRINTF("[readMultiline] start_match->rm_so != 0\n");
				// check if match + prematch + garbage is larger than glblGetMaxLine()
				if ((start_match->rm_eo)+(strlen(" (prematch@48577) "))	> (size_t)glblGetMaxLine() - headersReserve) {
					if(localDebug)
						DBGPRINTF("[readMultiline] (prematch@48577) oversize\n");
					// oversize
					// send many enough pieces so garbage get's collected as well
					// TODO implementation, take out prevMsgSegment and shorten with sent content
					CHKiRet(RS_RET_ERR);
				} else {
					if(localDebug)
						DBGPRINTF("[readMultiline] (prematch@48577) fits\n");
					uchar *prevMesg = rsCStrGetSzStrNoNULL(pThis->prevMsgSegment);
					// send the garbage as whole as it fits
					cstr_t *thisMessage = NULL;
					CHKiRet(cstrConstruct(&thisMessage));
					// header (the match)
					CHKiRet(rsCStrAppendStrWithLen(thisMessage, &(prevMesg[start_match->rm_so]), (start_match->rm_eo)-(start_match->rm_so)));
					// informative on the content
					CHKiRet(rsCStrAppendStr(thisMessage, (uchar*)" (prematch@48577) "));
					// the pre matched content
					CHKiRet(rsCStrAppendStrWithLen(thisMessage, rsCStrGetSzStrNoNULL(pThis->prevMsgSegment), (start_match->rm_so)));
					CHKiRet(rsCStrConstructFromCStr(ppCStr, thisMessage));
					cstrFinalize(*ppCStr);
					if(localDebug)
						DBGPRINTF("[readMultiline] prematch sending %s\n", (char*)rsCStrGetSzStrNoNULL(*ppCStr));
					cstrDestruct(&thisMessage);

					// slice out the start_match->rm_so until currOffs and copy to pThis->prevMsgSegment
					cstr_t *leftOverMessage = NULL;
					CHKiRet(cstrConstruct(&leftOverMessage));
					CHKiRet(rsCStrAppendStrWithLen(leftOverMessage, &(prevMesg[start_match->rm_so]), (cstrLen(pThis->prevMsgSegment)-start_match->rm_so)));
					cstrDestruct(&pThis->prevMsgSegment);
					CHKiRet(rsCStrConstructFromCStr(&pThis->prevMsgSegment, leftOverMessage));

					// garbage done
					iRet = RS_RET_OK;
					FINALIZE;
				}
			}
		}
		else if (nFound == 2) {
			//complete
			cstrFinalize(pThis->prevMsgSegment); // DEBUG
			uchar *prevMesg = rsCStrGetSzStrNoNULL(pThis->prevMsgSegment);
			if(localDebug) {
				DBGPRINTF("[readMultiline] nFound 2 line %s storedBol %d\n", (char*)prevMesg, bolOffset);
			}

			if (start_match->rm_so > glblGetMaxLine() - headersReserve) {
				if(localDebug)
					DBGPRINTF("[readMultiline] nFound 2 oversize\n");
				// oversize
				// TODO handle too large, save regex from previous send, concatenate message to header + (continuation@48577)?

				// oversize
				// TODO handle too large, save regex from previous send, concatenate message to header + (continuation@48577)?
				/*
				 *  make it like this:
				 *
				 *  1st match + rest of the message that fits +
				 *  " (oversized_message@48577) " or with " (oversized_message@48577 uuid="xxxx-yyy") "
				 *
				 *  2nd match + " (oversized_message@48577) " or with " (oversized_message@48577 uuid="xxxx-yyy") " +
				 *  "rest of the message that fits" +
				 *  in case still too large " (oversized_message@48577) " or with " (oversized_message@48577 uuid="xxxx-yyy") "
				 *
				 *  by this way we can use the 1st case only to generate them all and keep chain intact
				 */

				CHKiRet(RS_RET_ERR);
			}
			else {
				if(localDebug)
					DBGPRINTF("[readMultiline] nFound 2 fits\n");
				// it fits, send it
				cstr_t *thisMessage = NULL;
				CHKiRet(cstrConstruct(&thisMessage));
				if(localDebug)
					DBGPRINTF("[readMultiline] nFound 2 rm_so %d rm_eo %d\n", start_match->rm_so, start_match->rm_eo);
				CHKiRet(rsCStrAppendStrWithLen(thisMessage, prevMesg, start_match->rm_so));
				cstrFinalize(thisMessage); // DEBUG
				CHKiRet(rsCStrConstructFromCStr(ppCStr, thisMessage));
				cstrFinalize(*ppCStr);
				if(localDebug)
					DBGPRINTF("[readMultiline] nFound 2 sending %s\n", (char*)rsCStrGetSzStrNoNULL(*ppCStr));
				cstrDestruct(&thisMessage);


				// slice out the next_match
				cstr_t *nextMessage = NULL;
				CHKiRet(cstrConstruct(&nextMessage));
				CHKiRet(rsCStrAppendStrWithLen(nextMessage, &prevMesg[start_match->rm_so], start_match->rm_eo - start_match->rm_so));
				cstrFinalize(nextMessage); // DEBUG
				if(localDebug)
					DBGPRINTF("[readMultiline] nFound 2 from rm_so %d rm_eo %d (%d) storing %s\n",
							start_match->rm_so, start_match->rm_eo, start_match->rm_eo - start_match->rm_so,
							(char*)rsCStrGetSzStrNoNULL(nextMessage));
				cstrDestruct(&pThis->prevMsgSegment);
				CHKiRet(rsCStrConstructFromCStr(&pThis->prevMsgSegment, nextMessage));
				cstrDestruct(&nextMessage);

				//done
				iRet = RS_RET_OK;
				FINALIZE;
			}
		}
	}

	// check if at EOF and readTimeout should apply and we have something to send
	if (cstrLen(pThis->prevMsgSegment) > 0 &&
			iRet == RS_RET_EOF &&
			pThis->readTimeout &&
			(getTime(NULL) > pThis->lastRead + pThis->readTimeout)) {
		DBGPRINTF("[readMultiline] readTimeout\n");
		// prematch will be here if never matched, although in that case, no match occurs and we can send nothing
		if (nFound > 0) {
			// finalize so we have the null terminator
			cstrFinalize(pThis->prevMsgSegment);

			if (cstrLen(pThis->prevMsgSegment) > glblGetMaxLine() - headersReserve) {
				// oversize
				// TODO fetch header from matches
				// TODO oversize handling, start_match has already needed stuff for header persistence
				CHKiRet(RS_RET_ERR);
			}
			else {
				// remaining fits, flush through
				CHKiRet(rsCStrConstructFromCStr(ppCStr, pThis->prevMsgSegment));
				cstrFinalize(*ppCStr);
				DBGPRINTF("[readMultiline] readTimeout sending %s\n", (char*)rsCStrGetSzStrNoNULL(*ppCStr));
				cstrDestruct(&pThis->prevMsgSegment);
				iRet = RS_RET_OK;
			}
		}
	}


finalize_it:
	if (start_match != NULL)
		free(start_match);

	if (pThis->prevMsgSegment != NULL)
		cstrFinalize(pThis->prevMsgSegment);

	// persist location
	if (iRet == RS_RET_OK || iRet == RS_RET_EOF) {
		pThis->lastRead = getTime(NULL);
		pThis->strtOffs = pThis->iCurrOffs;
		*strtOffs = pThis->strtOffs;
	}
	DBGPRINTF("[readMultiline] return\n");
	return iRet;
}
