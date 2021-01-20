package sha_256

import (
	"fmt"
	"testing"
)

type test_data struct {
	name string
	args []byte
	want string
} 

func TestSha_256(t *testing.T) {
	var tests []test_data = []test_data { 
		{"tiny string", []byte("abc"),"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"medium string", []byte("The SHA (Secure Hash Algorithm) is one of a number of cryptographic hash functions. " +
		 "A cryptographic hash is like a signature for a data set. If you would like to compare two sets of raw data " +
		 "(source of the file, text or similar) it is always better to hash it and compare SHA256 values. It is like the " +
		 "fingerprints of the data. Even if only one symbol is changed the algorithm will produce different hash value. " +
		 "SHA256 algorithm generates an almost-unique, fixed size 256-bit (32-byte) hash. Hash is so called a one way function. " +
		 "This makes it suitable for checking integrity of your data, challenge hash authentication, anti-tamper, " + 
		 "digital signatures, blockchain."), "ae8bd70b42c2877e6800f3da2800044c8694f201242a484d38bb7941645e8876" },
		{"a little bigger", []byte("England is back in lockdown. It happened not a moment too soon. As of 2 November almost three-quarters of a million new cases have been officially counted since 21 September, when the government’s scientific advisory committee Sage advised lockdown. On that day, Britain had only had about 360,000 cases since Covid arrived. "+
		"Now the figure is three times that. So many more cases mean it will take longer, and possibly require tougher social restrictions, to get numbers down by imposing lockdown than it would have in September, says James Naismith, head of the Rosalind Franklin Institute in Oxford. "+
		"Naismith calculates that we will have 500 deaths per day in two to three weeks because of the cases that occurred over the past week, compared with an average of 144 in the week ending 2 November. But it could be far worse. "+
		"If we had done nothing for another two weeks, he says, we’d be looking at 1,000 deaths a day by Christmas – and more, if hospitals fill up and not everyone can get optimal treatment. No one is saying lockdowns are not harmful, they will cause misery and death, says Naismith. Being poorer as a country means we will be unhealthier. "+
		"We know despair and isolation take lives. We know delays in treating some (non-Covid) diseases will increase deaths.” It is clear, however, that Covid-19 is far deadlier, he says. But beating it back means people must follow the lockdown rules, and more closely than many did in spring. And that will be easier if there is a light at the end of this tunnel. "+
		"The brutal truth is that Boris Johnson’s pledge in July that Covid would be over by Christmas is as illusory as that promise proved back in the first world war. But we know that places that acted fast and forcefully enough to get infection down to low levels early on, then kept it there, with some distancing but also effective testing, tracing and quarantine, have been able to return to a degree of normality. "+
		"Life is largely normal in New Zealand; the South Korean test and trace response is widely regarded as the benchmark; Taiwan recently celebrated 200 days without a case; Vietnam hasn’t added to its death count of 35 since 5 September, and China, source of the virus, has so far avoided a second wave. "+
		"But given that the UK’s test and trace system is so shambolic, we appear to be relying on a vaccine to bail us out. Sadly, it’s more complicated than that. Even once discovered, manufactured and distributed, it won’t banish the virus immediately, says Prof David Salisbury of Imperial College London, a former director of immunisation at the Department of Health. "+
		"We will still need some distancing, and testing and quarantine to keep outbreaks under control. But we may not be condemned to the life we’re living now."), 
		"ef857ae6debee7e8705609ed3c90287e964717dd9789922227d4a2593e8a4f22" },
    }
	for _i, tt := range tests {
		
		t.Run(tt.name, func(t *testing.T) {
			fmt.Printf ("hashing %s\n\n", string(tt.args));
			var got string = Sha_256 (tt.args);
			if (got != tt.want) {
				t.Errorf("test %d: Sha_256() \n\ngot=%v\n\n, want=%v\n\n", _i, got, tt.want)
			}
		})
	}
}
