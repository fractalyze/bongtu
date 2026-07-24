// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract TransferVerifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant deltax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant deltay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant deltay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;

    
    uint256 constant IC0x = 14396311031571003988339939872481504997320718421634426809978524421610775524188;
    uint256 constant IC0y = 19001676451223749147276049686624269277757869802150154915468425809661107961549;
    
    uint256 constant IC1x = 3759990128173818537104768912407391170797833148604906758907221629070713916246;
    uint256 constant IC1y = 17347591581168246479714992314400266489376313732492238278529552841505750808070;
    
    uint256 constant IC2x = 3829148196995975550431375207889570256540534064107671913231525577823097993450;
    uint256 constant IC2y = 19517611161207762257483607404790467176687407917178601313648164075981792272890;
    
    uint256 constant IC3x = 9802675381833970359868594775840155978563354876901298280737922120235247889157;
    uint256 constant IC3y = 5674833662556764505031198001474676993574768313056411080057746787518799980327;
    
    uint256 constant IC4x = 15931066562107109121440240307444029997881059822618806354020809651306194133578;
    uint256 constant IC4y = 6332290493307148130848987260440456960036220337734750742704202600069097459033;
    
    uint256 constant IC5x = 17156467887112497904491815086610268380788465351473115052775060335461469345290;
    uint256 constant IC5y = 311332187631562485741306517332839163006097564424445721182879021884162201500;
    
    uint256 constant IC6x = 10619792898348244255855003713305380069973350751818574190420433802110615211295;
    uint256 constant IC6y = 6806694977354058806858182232254808082303904315810043486243799724041351919575;
    
    uint256 constant IC7x = 12628990863053325148551076423602219303077514869201390942552192741736466250656;
    uint256 constant IC7y = 19003357884172388516575384122442406422546023067062415114266226975742971732967;
    
    uint256 constant IC8x = 17593435319147862807256264337577227830418050008830963816294537846949940902135;
    uint256 constant IC8y = 21320116741102520228379625590361055905981299997857016931677305371673014270659;
    
    uint256 constant IC9x = 5094045186888498246412757346854968463479775604467150774770192324216444642830;
    uint256 constant IC9y = 18793452253305591503575407624192281595047286127835678690901119626564275003091;
    
    uint256 constant IC10x = 4046466371732832811008215632717008468394727926182424591649490625825424963200;
    uint256 constant IC10y = 3064639038153260242763413171046222450037712634105949651331595314577061661138;
    
    uint256 constant IC11x = 21353967792966022308337084588447278492246983538381569743141771695017102890731;
    uint256 constant IC11y = 1743808134208536570810762484878882966885321376842388627814412832247921778080;
    
    uint256 constant IC12x = 21776027020096835751277566457264906033054522385998173502107981678791097211849;
    uint256 constant IC12y = 3949641122434647825394409456743675625596918380794304279596767689871465074226;
    
    uint256 constant IC13x = 9069126194896695892897252611603227329676420009008481436150582167422091014938;
    uint256 constant IC13y = 6608870736030261568719952049125689798597583697696330683435063522696584839515;
    
    uint256 constant IC14x = 10711273011110143470236432437800796563908345642521744228242273952148038150309;
    uint256 constant IC14y = 19363072967063348406435635313389159353904889430086816872742840902343400412437;
    
    uint256 constant IC15x = 13161145568620867321586175842074414141272190899597579635861526206917223997436;
    uint256 constant IC15y = 15366494767319925734861071102050933025236957635279499874207824017007298166020;
    
    uint256 constant IC16x = 13621607476193724997190150479572168786548897963630183347019617559573153418444;
    uint256 constant IC16y = 6147135879936915629973068996196033686177990970565896941340912194436587041757;
    
    uint256 constant IC17x = 14583426878104632738014871759429838861503538125464735968076758961467681499528;
    uint256 constant IC17y = 4701974285460538713390648507464955852695855667402103091713416007035634592690;
    
    uint256 constant IC18x = 9365205873414279838113198993433894923648785011308955102712912614636273945156;
    uint256 constant IC18y = 17389459634217373413517273853087226095029511226466343140301112584424762014234;
    
    uint256 constant IC19x = 18192953223566970004707064963264951948094472302579493988198505955376899995566;
    uint256 constant IC19y = 11159019232291390445986020947622281527768397200628690972807121794336000388090;
    
    uint256 constant IC20x = 16807856260922949736570312729845593333109123412444400022089490555478646201487;
    uint256 constant IC20y = 9207957189795531400397850696362113333139572909568991137291141933581515256135;
    
    uint256 constant IC21x = 7048979250745764924756250979901410683328110715815071568180814394482572178431;
    uint256 constant IC21y = 13738453972076461719892050314113572001324517768996281057682046730903871439314;
    
    uint256 constant IC22x = 5008713323330925896122875340127609749645534103010660323494497134081653628790;
    uint256 constant IC22y = 2533332808960664930619212478112741241501479743397548227413453826061456783604;
    
    uint256 constant IC23x = 18914826425517545323570978209237741341469629704579504503559574667322878558699;
    uint256 constant IC23y = 11123098940625332259953105985909111431151446292757255042303460644303688601278;
    
    uint256 constant IC24x = 20748314462709460749953489541860206902826019300410720040148688971310874116378;
    uint256 constant IC24y = 936174180991982751280085791687244472328947637278727440192278064221756884349;
    
    uint256 constant IC25x = 12554994781055681044034512791221930540943914652550525596539092273133153322030;
    uint256 constant IC25y = 1486455501931757246303780882580288556091971012117159640543103950720171548802;
    
    uint256 constant IC26x = 15642719732410265041466192709123897690325371029507722535562908290192923681541;
    uint256 constant IC26y = 19928056272585432450812300263246677727332268250299786807644802883139867917323;
    
    uint256 constant IC27x = 3918903764451356011264605997268517201575943248539908283260549483502017103091;
    uint256 constant IC27y = 13764320146514030790659437639530854750340848526308521607384327312885452161566;
    
    uint256 constant IC28x = 16942350572327603875414465008608920097634983689508183473161310782815166674631;
    uint256 constant IC28y = 10628214204531139721550307490242544817551604788226474857425013768811477078710;
    
    uint256 constant IC29x = 16485609281140492360291379416465704902066889112548622139226711059392552594461;
    uint256 constant IC29y = 9601963297161766879457100041331274125487446968437732931954328758975155822751;
    
    uint256 constant IC30x = 16936557515897809580362658902631380800303683951199861205579759489285726441678;
    uint256 constant IC30y = 11802670093577274198057845669146950956685469422596900071704204633408354340882;
    
    uint256 constant IC31x = 18407376076541841644156505128841364397915152301294932660737486158125600874165;
    uint256 constant IC31y = 10757099217938628286026037323128067620755813220661805631000580936441061719755;
    
    uint256 constant IC32x = 16163583322620746759699057374321699781371103557905228770656134825786590877708;
    uint256 constant IC32y = 17678289705745725499710236739628268180838841415476288404787340413654874989320;
    
    uint256 constant IC33x = 16570926010622169034089584275966505333731820875653705217231292134070541397139;
    uint256 constant IC33y = 482026103599729787608118999488939817721595828638151918935366535450880090793;
    
    uint256 constant IC34x = 17246708418156569443885816888494825366031950886696132002104015911555106394729;
    uint256 constant IC34y = 921468152455429469655668303551856695255458905523580002672441505176472239660;
    
    uint256 constant IC35x = 14291591318355092439656218670005680087610887740791118951920982848014235515117;
    uint256 constant IC35y = 17773792002405243789458783105278126464229557790712372700262998317726709983942;
    
    uint256 constant IC36x = 5391229583646429345684930517489343428021125610665935815056365652161413283518;
    uint256 constant IC36y = 13664763521747273107174517176082283292697137398204957313828985821535754955265;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[36] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                
                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))
                
                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))
                
                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))
                
                g1_mulAccC(_pVk, IC31x, IC31y, calldataload(add(pubSignals, 960)))
                
                g1_mulAccC(_pVk, IC32x, IC32y, calldataload(add(pubSignals, 992)))
                
                g1_mulAccC(_pVk, IC33x, IC33y, calldataload(add(pubSignals, 1024)))
                
                g1_mulAccC(_pVk, IC34x, IC34y, calldataload(add(pubSignals, 1056)))
                
                g1_mulAccC(_pVk, IC35x, IC35y, calldataload(add(pubSignals, 1088)))
                
                g1_mulAccC(_pVk, IC36x, IC36y, calldataload(add(pubSignals, 1120)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            
            checkField(calldataload(add(_pubSignals, 864)))
            
            checkField(calldataload(add(_pubSignals, 896)))
            
            checkField(calldataload(add(_pubSignals, 928)))
            
            checkField(calldataload(add(_pubSignals, 960)))
            
            checkField(calldataload(add(_pubSignals, 992)))
            
            checkField(calldataload(add(_pubSignals, 1024)))
            
            checkField(calldataload(add(_pubSignals, 1056)))
            
            checkField(calldataload(add(_pubSignals, 1088)))
            
            checkField(calldataload(add(_pubSignals, 1120)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
