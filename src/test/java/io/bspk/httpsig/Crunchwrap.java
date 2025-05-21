package io.bspk.httpsig;

import java.util.stream.Collectors;

import com.google.common.base.CharMatcher;
import com.google.common.base.Splitter;

public class Crunchwrap {

	/**
	 * Unwrap a string per RFC 8792
	 */
	public static String unwrap(String wrapped) {
		
		boolean[] isWrapping = {false}; // this uses an array to get around java's immutable inner variable limitation
		String unwrapped = Splitter.on("\n").splitToList(wrapped).stream()
			.map(line -> {
				if (isWrapping[0]) {
					line = CharMatcher.whitespace().trimLeadingFrom(line); // if we're wrapping, trim the leading whitespace from the value
				}
				
				if (line.endsWith("\\")) {
					isWrapping[0] = true; // if we end with a newline, the next line is wrapped
					line = CharMatcher.is('\\').trimTrailingFrom(line); // trim the trailing backslash
				} else {
					isWrapping[0] = false;
					line = line + '\n'; // we add back a newline since it's not wrapping to the next line
				}
				return line;
			}).collect(Collectors.joining()); // note this removes all the internal newlines, too
		
		// awkwardly trim off the trailing newline
		if (unwrapped.endsWith("\n")) {
			unwrapped = unwrapped.substring(0, unwrapped.length() - 1);
		}
		
		return unwrapped;
	}	

}
