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

contract Groth16Verifier {
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

    
    uint256 constant IC0x = 3707057265117880688977265245920910497570276034221903353653398439972877043374;
    uint256 constant IC0y = 19079196817976099216718258546986648380970695375157612364146130499078115322628;
    
    uint256 constant IC1x = 14664569549221170976426174531489277710828971785243075049603009687760372549215;
    uint256 constant IC1y = 9420648967052381812994558984408271606088005428013490880257174698548602256589;
    
    uint256 constant IC2x = 82970915088387958669775318130297248403868650386186653417934582863259848722;
    uint256 constant IC2y = 16783921182793117745899793621022763885848868679738866813714703928861783897945;
    
    uint256 constant IC3x = 2259588404782526114927853848369369549930181287648781030621981071890721009779;
    uint256 constant IC3y = 2006058041715191684647976180150385641623716386718345743903420192190857539363;
    
    uint256 constant IC4x = 9934710176595759447652707638017813812889003773383961205410580867453603074051;
    uint256 constant IC4y = 6409619179851804115210183371094159239977143960385976556568150020056947469417;
    
    uint256 constant IC5x = 5261399945716151152285376574703893342633909348851392028923225793078344423619;
    uint256 constant IC5y = 20911310482884676770926137249048398562699140195133991182341803114285414746588;
    
    uint256 constant IC6x = 7911424983499674195600262846537011045445482431764261260170232285815900211346;
    uint256 constant IC6y = 7957988699879920482943892319378985877578549429253892626962921501414178467753;
    
    uint256 constant IC7x = 6755964968114717686365441987682236367501411893199330270304479802575938073907;
    uint256 constant IC7y = 8821977951957120227887815852057916472697655331818063713399217526843657234886;
    
    uint256 constant IC8x = 9220361793018216084196488026359198074895839698562842001022719364561469387713;
    uint256 constant IC8y = 14819067998327442098520832713061059572798852427501394329896026077965518214502;
    
    uint256 constant IC9x = 16152183345793102986934383767375742469019646865502595491138296072216704770152;
    uint256 constant IC9y = 8898738277042715495051158800031406820719533090867255834748936245887132009903;
    
    uint256 constant IC10x = 18786350115359395686176115050947886749713758202449117240112447433677409864949;
    uint256 constant IC10y = 16488141080207337029100999308721459631559797333675980308582714590717319266151;
    
    uint256 constant IC11x = 1294750460657223653097011986586951272332804184970527866746066990461007499726;
    uint256 constant IC11y = 8870791930942357854700041206052759713651837770576142100477261415952483180935;
    
    uint256 constant IC12x = 18155306618946621936096512983267640402469526930213045790181429335036589653521;
    uint256 constant IC12y = 11890880507087426828262920082312366492016774482220526055462865054094475767327;
    
    uint256 constant IC13x = 15545021614522085270599910944155749508562212365491358755201502956356084703759;
    uint256 constant IC13y = 9363519900012803402312924836964643252936930442936317115959467816438413856345;
    
    uint256 constant IC14x = 30095760847582783372672861226709477137196327878838358593777202015894516660;
    uint256 constant IC14y = 14015034589528383263141846316124390207664956759610658735719708456323332937390;
    
    uint256 constant IC15x = 18848516946908380182147020835255542757647940221762373828419887416136601912494;
    uint256 constant IC15y = 8928924174127443355965067702275863877732168731499787764569228009546336080151;
    
    uint256 constant IC16x = 20217136100417155107782053132976237159078508793268236583825690508109559332476;
    uint256 constant IC16y = 14351788040383451345344000070064715648019973113171481213211331351308454719717;
    
    uint256 constant IC17x = 14923992643106987200230471640216579883588610738162491544941416945973094832757;
    uint256 constant IC17y = 7723129747484618061079838113019254561718189401009554924093815363823304274168;
    
    uint256 constant IC18x = 16461221810860589226972581995706578685793717200613246213041592114501255857901;
    uint256 constant IC18y = 17321941908550403254431233999891285481790480563951313059307751517150233929612;
    
    uint256 constant IC19x = 4480154742758149161580941449402612381643804808032035557875968981622871360590;
    uint256 constant IC19y = 14242701162349268309038619952632087651759700038393281884437817228182853431040;
    
    uint256 constant IC20x = 14488663368291842496560580487520360716895493780641478920565352224380811936117;
    uint256 constant IC20y = 6045681926776826629461853922410420743778729153627902341615995597156665591996;
    
    uint256 constant IC21x = 4365643773256018856738443357011572131299313276197207268776903878656151131427;
    uint256 constant IC21y = 4221529137636986773802291251071260804151251930751907713893735133261578459518;
    
    uint256 constant IC22x = 4104438877370908782217329076723127457158330685660300503301694915585880238943;
    uint256 constant IC22y = 8785776827035995002127385215469077971973337257704697435684289905161643526896;
    
    uint256 constant IC23x = 12045801888633439205254585638003168521925759947283434327668669184673391559147;
    uint256 constant IC23y = 10343634160536528864633452327799263326615410457754923167934758679093457088021;
    
    uint256 constant IC24x = 21750781007780153507894214900801783105393228790972542864272349715090319115341;
    uint256 constant IC24y = 7275653902501804497963331774302803018636696188929263319838322687354173845001;
    
    uint256 constant IC25x = 6458528181556565292202974851345426001266580834297573911771505744019957958307;
    uint256 constant IC25y = 14445108774576267847070065302989457127235670262607387925575585042914566965071;
    
    uint256 constant IC26x = 2520679310753767263626591586197677180449522956866627879083515706814613673542;
    uint256 constant IC26y = 6886245023248893869611160148798520221715667158739241445953082232085020323415;
    
    uint256 constant IC27x = 13143864496639189965399924342794698954513410620618702919017588614057493530175;
    uint256 constant IC27y = 13656335854676167207149312291065308158489347608070641937328922387673664479534;
    
    uint256 constant IC28x = 6975828914824946789436921131196175298953349182417011701233339005958709230347;
    uint256 constant IC28y = 5278210940624718843653994048790689997169676679796221658300934421160973537565;
    
    uint256 constant IC29x = 9158833268485282210755669867728948914297004737345796463018390414887887561987;
    uint256 constant IC29y = 6293392640450961378037680571643101953099167514054452155218574833429562448413;
    
    uint256 constant IC30x = 18897377751951238360901547800904240091498997445885683069482263434597460777081;
    uint256 constant IC30y = 14256864670008670006841225271509130556295590831527711953957154712727510043325;
    
    uint256 constant IC31x = 13289731644065857589861930951728435921878095403640473459632798814968273151611;
    uint256 constant IC31y = 2023242219991978223535956703153437024961667394659645412557884178030806758271;
    
    uint256 constant IC32x = 15923617041631070982097772445622307324227231036047795514045425768523420672225;
    uint256 constant IC32y = 15155258520106153750564792512684904191324980865375655975667656935810343428433;
    
    uint256 constant IC33x = 20846191943821794457713451893398016584869390640931861102227395568490186779582;
    uint256 constant IC33y = 1346240930415263835197181376089383585337334966085819729233285813936950850254;
    
    uint256 constant IC34x = 15834719338326273443894900758279532879734711455991786859519239104448455986539;
    uint256 constant IC34y = 17841054089450266980042087794151954308129667628120084195567726212482220296723;
    
    uint256 constant IC35x = 7632432205920510992122035882343640916695309399219203315271059315157292128738;
    uint256 constant IC35y = 6879442256545988205600884349675605532023675578311481435582606103500325975427;
    
    uint256 constant IC36x = 2082601882383077958914768881110137763218733917600190889228752007188244292412;
    uint256 constant IC36y = 414426715993143237662209510784593035566819589810580308964300517084747547798;
    
    uint256 constant IC37x = 9930953172037078482239082931720681652095773062098509509394922378609987637876;
    uint256 constant IC37y = 2704352720422737917694256401686559400699056663193866590658924975106398408589;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[37] calldata _pubSignals) public view returns (bool) {
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
                
                g1_mulAccC(_pVk, IC37x, IC37y, calldataload(add(pubSignals, 1152)))
                

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
            
            checkField(calldataload(add(_pubSignals, 1152)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
